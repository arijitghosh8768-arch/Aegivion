"""Part 7 — final stage: evaluation systems A–F, the 18-scenario
suite, spec metrics (incl. detection latency and lead time), the
leave-one-out ablation study, temporal TRAIN/VALIDATION/TEST
threshold tuning, error analysis, performance benchmarks, the
framework-free REST API, the independence gates, and the 17-step
final acceptance test.

Every number asserted here is measured, never fabricated: the
corpus is synthetic (``label_source="synthetic"``), deterministic
(seeded anomaly model), and the preferred finding wording is
"Potential Cloud Destructive Activity" — never a claim of
confirmed ransomware or perfect detection.
"""

from __future__ import annotations

import ast
import inspect
import json
import sys
from dataclasses import fields as dataclass_fields
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from algo.detection.cloud_destruction.api import (
    ANALYZE_THRESHOLD,
    analyze,
    get_destructive_session,
    get_finding_explanation,
    get_protection_profile,
    list_findings,
)
from algo.detection.cloud_destruction.ablation import run_ablation
from algo.detection.cloud_destruction.benchmark import run_benchmarks
from algo.detection.cloud_destruction.contract import (
    FINDING_TYPE,
    build_finding_contract,
)
from algo.detection.cloud_destruction.detector import DestructionDetector
from algo.detection.cloud_destruction.error_analysis import (
    FalseNegativeRecord,
    FalsePositiveRecord,
    analyze_errors,
)
from algo.detection.cloud_destruction.evaluation import (
    HIGH_RISK_THRESHOLD,
    LabeledCorpus,
    VARIANTS,
    evaluate_variants,
    measure_detection_latency,
    temporal_threshold_tuning,
)
from algo.detection.cloud_destruction.explainability import (
    FINDING_LABEL,
    DestructiveBehaviorCategory,
)
from algo.detection.cloud_destruction.normalizer import ResourceActivityNormalizer
from algo.detection.cloud_destruction.scenarios import (
    ATTACK_CHAIN,
    SCENARIOS,
    acceptance_attack_chain,
    mark_critical,
    scenario_by_number,
)
from algo.detection.cloud_destruction.schemas import ResourceActivityEvent
from algo.detection.cloud_destruction.storage import DestructionRepository
from algo.detection.cloud_destruction.tests.helpers import BASE_TIME

#: Scenario corpus: the 18 evaluation scenarios, each starting
#: 50h after the previous one so sessionization never bleeds
#: across scenarios.
CORPUS_BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCENARIO_SPACING_HOURS = 50
THRESHOLD = 0.35

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PACKAGE_ROOT = _REPO_ROOT / "detection" / "cloud_destruction"
_INGESTION_ROOT = _REPO_ROOT / "ingestion"

#: The spec's 18 scenario names, in order.
SPEC_SCENARIO_NAMES = (
    "normal_writes",
    "normal_cleanup",
    "lifecycle_expiration",
    "backup_retention_cleanup",
    "normal_deployment",
    "large_legitimate_migration",
    "mass_object_modification",
    "mass_object_deletion",
    "mass_version_deletion",
    "snapshot_deletion",
    "backup_recovery_point_deletion",
    "protection_degradation",
    "mass_rewrite_pattern",
    "slow_destructive_behavior",
    "compound_destructive_behavior",
    "mixed_benign_malicious",
    "missing_telemetry",
    "out_of_order_events",
)

POSITIVE_SCENARIO_NAMES = tuple(
    scenario.name for scenario in SCENARIOS if scenario.expected_positive
)
NEGATIVE_SCENARIO_NAMES = tuple(
    scenario.name for scenario in SCENARIOS if not scenario.expected_positive
)


def _scenario_corpus():
    """Build the deterministic 18-scenario labeled corpus."""
    events: list[ResourceActivityEvent] = []
    labels: dict[str, str] = {}
    for scenario in SCENARIOS:
        built = mark_critical(
            scenario.events(
                CORPUS_BASE
                + timedelta(hours=SCENARIO_SPACING_HOURS * scenario.number)
            )
        )
        for event in built:
            labels[event.event_id] = scenario.name
            events.append(event)
    positive_ids = frozenset(
        event_id
        for event_id, name in labels.items()
        if name in POSITIVE_SCENARIO_NAMES
    )
    negative_ids = frozenset(
        event_id
        for event_id, name in labels.items()
        if name in NEGATIVE_SCENARIO_NAMES
    )
    corpus = LabeledCorpus(
        events=tuple(events),
        positive_event_ids=positive_ids,
        negative_event_ids=negative_ids,
        label_source="synthetic",
        description=(
            "18-scenario synthetic corpus; scenarios spaced 50h apart"
        ),
    )
    return corpus, labels


# ---------------------------------------------------------------------- #
# Deterministic evaluation fixtures (each runs the seeded detector once)
# ---------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def scenario_corpus():
    return _scenario_corpus()


@pytest.fixture(scope="module")
def variant_results(scenario_corpus):
    return evaluate_variants(scenario_corpus[0], threshold=THRESHOLD)


@pytest.fixture(scope="module")
def ablation_study(scenario_corpus):
    corpus, labels = scenario_corpus
    return run_ablation(
        list(corpus.events),
        labels,
        positive_scenarios=POSITIVE_SCENARIO_NAMES,
        threshold=THRESHOLD,
    )


@pytest.fixture(scope="module")
def error_report(scenario_corpus):
    corpus, labels = scenario_corpus
    return analyze_errors(
        list(corpus.events),
        labels,
        positive_scenarios=POSITIVE_SCENARIO_NAMES,
        threshold=THRESHOLD,
    )


@pytest.fixture(scope="module")
def error_report_low_threshold(scenario_corpus):
    """Error analysis at a 0.05 threshold: the benign sessions
    score above it, exercising the false-positive record path
    with real (not fabricated) data."""
    corpus, labels = scenario_corpus
    return analyze_errors(
        list(corpus.events),
        labels,
        positive_scenarios=POSITIVE_SCENARIO_NAMES,
        threshold=0.05,
    )


@pytest.fixture(scope="module")
def threshold_tuning(scenario_corpus):
    return temporal_threshold_tuning(scenario_corpus[0])


@pytest.fixture(scope="module")
def attack_events():
    return acceptance_attack_chain(BASE_TIME)


@pytest.fixture(scope="module")
def attack_outcome(attack_events):
    return DestructionDetector().detect(list(attack_events))


# ---------------------------------------------------------------------- #
# Alignment helpers: the detector emits parallel lists per session
# ---------------------------------------------------------------------- #


def _attack_session(outcome):
    """The kill-chain session: the largest session of the chain."""
    return max(outcome.sessions, key=lambda session: session.event_count)


def _finding_for(outcome, session):
    return next(
        finding
        for finding in outcome.findings
        if finding.session_id == session.session_id
    )


def _categories_for(outcome, finding):
    index = next(
        index
        for index, candidate in enumerate(outcome.findings)
        if candidate.finding_id == finding.finding_id
    )
    return set(outcome.categories[index])


def _vector_for(outcome, session):
    return next(
        vector
        for vector in outcome.feature_vectors
        if vector.session_id == session.session_id
    )


def _report_for(outcome, finding):
    return next(
        report
        for report in outcome.validation_reports
        if report.session_id == finding.session_id
    )


def _explanation_for(outcome, finding):
    return next(
        explanation
        for explanation in outcome.explanations
        if explanation.session_id == finding.session_id
    )


# ---------------------------------------------------------------------- #
# Scenario suite
# ---------------------------------------------------------------------- #


class TestScenarioSuite:
    def test_eighteen_spec_scenarios_present(self):
        assert len(SCENARIOS) == 18
        assert [scenario.number for scenario in SCENARIOS] == list(range(1, 19))
        assert tuple(scenario.name for scenario in SCENARIOS) == (
            SPEC_SCENARIO_NAMES
        )

    def test_scenario_registry_lookup(self):
        assert scenario_by_number(7).name == "mass_object_modification"
        assert scenario_by_number(18).name == "out_of_order_events"
        assert ATTACK_CHAIN.number == 0
        assert ATTACK_CHAIN.expected_positive is True

    def test_labels_split_destructive_from_benign(self):
        assert len(POSITIVE_SCENARIO_NAMES) == 12  # scenarios 7–18
        assert len(NEGATIVE_SCENARIO_NAMES) == 6  # scenarios 1–6
        assert not set(POSITIVE_SCENARIO_NAMES) & set(NEGATIVE_SCENARIO_NAMES)

    def test_corpus_is_labeled_and_synthetic(self, scenario_corpus):
        corpus, labels = scenario_corpus
        assert isinstance(corpus, LabeledCorpus)
        assert corpus.label_source == "synthetic"
        assert len(corpus.events) == len(labels)
        assert not corpus.positive_event_ids & corpus.negative_event_ids
        assert corpus.positive_event_ids | corpus.negative_event_ids == frozenset(
            labels
        )


# ---------------------------------------------------------------------- #
# Evaluation systems A–F and the primary research question
# ---------------------------------------------------------------------- #


class TestVariantComparison:
    def test_all_six_variants_evaluated(self, variant_results):
        assert set(variant_results) == {"deletion_threshold"} | set(VARIANTS)

    def test_multi_signal_detector_outperforms_simple_baselines(
        self, variant_results
    ):
        """Primary research question: the full multi-signal detector
        identifies destructive behavior more reliably than a simple
        deletion-count threshold or rule-only detection."""
        full = variant_results["full"]
        deletion_threshold = variant_results["deletion_threshold"]
        rules_only = variant_results["rules_only"]
        # recall: more destructive scenarios caught
        assert full.recall > deletion_threshold.recall
        assert full.recall > rules_only.recall
        # F1 dominates both simple baselines
        assert full.f1 > deletion_threshold.f1
        assert full.f1 > rules_only.f1
        # PR-AUC — the emphasized metric for rare destructive events
        assert full.pr_auc >= deletion_threshold.pr_auc
        assert full.pr_auc >= rules_only.pr_auc

    def test_metrics_within_unit_range(self, variant_results):
        for result in variant_results.values():
            for metric in (
                "precision",
                "recall",
                "f1",
                "pr_auc",
                "roc_auc",
                "false_positive_rate",
                "false_negative_rate",
                "precision_at_high_risk",
                "recall_at_fixed_fpr",
            ):
                value = getattr(result, metric)
                assert 0.0 <= value <= 1.0, (result.variant, metric, value)

    def test_label_provenance_is_synthetic(self, variant_results):
        for result in variant_results.values():
            assert result.label_source == "synthetic"

    def test_full_detector_low_false_positive_rate(self, variant_results):
        full = variant_results["full"]
        assert full.false_positive_rate <= 0.05
        assert full.precision >= 0.95
        assert full.recall >= 0.9
        # emphasized metrics: precision at high-risk threshold and
        # recall at a fixed false-positive rate
        assert full.precision_at_high_risk >= 0.9
        assert full.recall_at_fixed_fpr >= 0.9

    def test_deletion_threshold_variant_is_a_count_rule(self, variant_results):
        variant_a = variant_results["deletion_threshold"]
        assert variant_a.threshold == 5
        assert "decision_rule" in variant_a.raw


# ---------------------------------------------------------------------- #
# Scenario-level evaluation
# ---------------------------------------------------------------------- #


class TestScenarioEvaluation:
    def test_all_eighteen_scenarios_scored(self, ablation_study):
        baseline = ablation_study.baseline
        assert baseline.n_scenarios == 18
        assert set(baseline.scenario_scores) == (
            set(POSITIVE_SCENARIO_NAMES) | set(NEGATIVE_SCENARIO_NAMES)
        )

    def test_no_false_positives_at_scenario_level(self, ablation_study):
        baseline = ablation_study.baseline
        assert baseline.precision == 1.0
        assert baseline.false_positive_rate == 0.0

    def test_nearly_all_destructive_scenarios_detected(self, ablation_study):
        baseline = ablation_study.baseline
        assert len(baseline.detected_scenarios) >= 11
        assert set(baseline.detected_scenarios) <= set(POSITIVE_SCENARIO_NAMES)


# ---------------------------------------------------------------------- #
# Detection latency and lead time
# ---------------------------------------------------------------------- #


class TestDetectionMetrics:
    def test_detection_latency_and_lead_time_measured(self, attack_events):
        attack_ids = frozenset(
            event.event_id
            for event in attack_events
            if not event.event_id.startswith("ac-h")
        )
        latency = measure_detection_latency(
            DestructionDetector(),
            list(attack_events),
            positive_event_ids=attack_ids,
            threshold=THRESHOLD,
        )
        assert latency["method"] == "chronological_prefix_redetection"
        assert latency["n_tracked_sessions"] == 1
        assert latency["n_detected"] == 1
        assert latency["mean_detection_latency_seconds"] >= 0.0
        assert latency["median_detection_latency_seconds"] >= 0.0
        # detection happens *during* the attack, not after it ended
        assert latency["mean_lead_time_seconds"] > 0.0

    def test_detection_is_early_with_substantial_lead_time(self, attack_events):
        """The kill chain runs for 330s; detection fires on the
        modification burst (seconds in), leaving most of the chain
        as lead time."""
        attack_ids = frozenset(
            event.event_id
            for event in attack_events
            if not event.event_id.startswith("ac-h")
        )
        latency = measure_detection_latency(
            DestructionDetector(),
            list(attack_events),
            positive_event_ids=attack_ids,
            threshold=THRESHOLD,
        )
        assert latency["mean_detection_latency_seconds"] < 60.0
        assert latency["mean_lead_time_seconds"] > 240.0


# ---------------------------------------------------------------------- #
# Ablation study
# ---------------------------------------------------------------------- #


class TestAblationStudy:
    def test_full_baseline_plus_seven_leave_one_out_runs(self, ablation_study):
        assert ablation_study.baseline.name == "full"
        assert {result.name for result in ablation_study.results} == {
            "without_baseline",
            "without_sequence",
            "without_ml",
            "without_recovery_analysis",
            "without_recoverability",
            "without_criticality",
            "without_arde",
        }

    def test_full_detector_is_never_worse_than_an_ablation(self, ablation_study):
        baseline = ablation_study.baseline
        for result in ablation_study.results:
            assert baseline.f1 >= result.f1 - 1e-9, result.name

    def test_sequence_ml_and_criticality_each_contribute(self, ablation_study):
        baseline = ablation_study.baseline
        for name in ("without_sequence", "without_ml", "without_criticality"):
            result = next(
                candidate
                for candidate in ablation_study.results
                if candidate.name == name
            )
            assert result.f1 < baseline.f1 - 0.05, name

    def test_ablations_report_complete_metrics(self, ablation_study):
        for result in (ablation_study.baseline, *ablation_study.results):
            assert result.n_sessions > 0
            assert 0.0 <= result.pr_auc <= 1.0
            assert 0.0 <= result.roc_auc <= 1.0
            assert 0.0 <= result.false_positive_rate <= 1.0
            assert result.scenario_scores
            if result.name != "full":
                assert result.delta_vs_full


# ---------------------------------------------------------------------- #
# Temporal threshold tuning (TRAIN / VALIDATION / TEST)
# ---------------------------------------------------------------------- #


class TestThresholdTuning:
    def test_temporal_split_is_train_validation_test(self, threshold_tuning):
        assert set(threshold_tuning.split) == {"train", "validation", "test"}
        for name in ("train", "validation", "test"):
            assert threshold_tuning.split[name]["n_sessions"] > 0
        # temporal order: oldest → train, middle → validation, newest → test
        assert threshold_tuning.split["train"]["rule"] == "oldest third"
        assert threshold_tuning.split["validation"]["rule"] == "middle third"
        assert threshold_tuning.split["test"]["rule"] == "newest third"

    def test_threshold_selected_on_validation_never_test(self, threshold_tuning):
        assert threshold_tuning.raw["test_touched_during_selection"] is False
        assert (
            threshold_tuning.raw["selection_rule"]
            == "max validation F1; ties break to highest threshold"
        )
        # the tuned threshold is the validation-F1 argmax
        # under the documented rule: max F1, ties break to
        # the highest threshold (never the test set)
        best = max(
            threshold_tuning.validation_f1,
            key=lambda t: (
                threshold_tuning.validation_f1[t],
                float(t),
            ),
        )
        assert f"{threshold_tuning.tuned_threshold:.2f}" == best
        assert threshold_tuning.tuned_threshold in (
            threshold_tuning.thresholds_evaluated
        )

    def test_all_three_splits_reported_honestly(self, threshold_tuning):
        for name in ("train_metrics", "validation_metrics", "test_metrics"):
            metrics = getattr(threshold_tuning, name)
            assert {"precision", "recall", "f1"} <= set(metrics)
        # honest reporting: the oldest third is all-benign, so its
        # train F1 is a true zero — never a fabricated number
        assert threshold_tuning.train_metrics["f1"] == 0.0
        assert threshold_tuning.validation_metrics["f1"] == 1.0
        assert threshold_tuning.test_metrics["f1"] > 0.9


# ---------------------------------------------------------------------- #
# Error analysis
# ---------------------------------------------------------------------- #


class TestErrorAnalysis:
    def test_operating_threshold_has_no_false_positives(self, error_report):
        assert error_report.threshold == THRESHOLD
        assert error_report.n_false_positives == 0
        assert error_report.n_false_negatives == 1
        assert error_report.false_negatives[0].scenario == "mixed_benign_malicious"

    def test_false_positive_record_schema(self):
        required = {
            "scenario",
            "session_id",
            "actor_id",
            "risk_score",
            "confidence_score",
            "severity",
            "resource_types",
            "activity_pattern",
            "top_contributing_signals",
            "baseline_quality",
            "schedule_context",
            "recovery_state",
            "model_output",
            "arde_result",
        }
        assert required <= {field.name for field in dataclass_fields(FalsePositiveRecord)}

    def test_false_negative_record_schema(self):
        required = {
            "scenario",
            "session_id",
            "actor_id",
            "risk_score",
            "missing_signal",
            "destructive_event_count",
            "insufficient_telemetry",
            "sequence_failure",
            "baseline_failure",
            "model_failure",
        }
        assert required <= {field.name for field in dataclass_fields(FalseNegativeRecord)}

    def test_false_positive_records_carry_spec_context(
        self, error_report_low_threshold
    ):
        # at a 0.05 threshold the benign sessions score above it,
        # so the false-positive path is exercised with real data
        assert error_report_low_threshold.n_false_positives > 0
        first = error_report_low_threshold.false_positives[0]
        assert isinstance(first, FalsePositiveRecord)
        assert first.resource_types  # resource type
        assert isinstance(first.activity_pattern, dict)  # activity pattern
        assert first.activity_pattern
        assert isinstance(first.top_contributing_signals, list)
        assert first.top_contributing_signals  # top contributing signals
        assert all(
            isinstance(entry, tuple) and len(entry) == 2
            for entry in first.top_contributing_signals
        )
        assert first.baseline_quality is not None  # baseline quality
        assert isinstance(first.schedule_context, dict)  # schedule context
        assert isinstance(first.recovery_state, dict)  # recovery state
        assert isinstance(first.model_output, dict)  # model output
        assert isinstance(first.arde_result, dict)  # ARDE result
        assert "overall" in first.arde_result
        # every record carries the full spec-mandated context
        for record in error_report_low_threshold.false_positives:
            assert {
                "resource_types",
                "activity_pattern",
                "top_contributing_signals",
                "baseline_quality",
                "schedule_context",
                "recovery_state",
                "model_output",
                "arde_result",
            } <= set(record.to_log_dict())

    def test_false_negative_diagnostics_populated(self, error_report):
        record = error_report.false_negatives[0]
        assert isinstance(record, FalseNegativeRecord)
        # the missed session is the benign actor inside the
        # mixed scenario: its destructive-event count is an
        # honest zero, not a fabricated number
        assert record.destructive_event_count >= 0
        assert isinstance(record.missing_signal, dict)
        assert isinstance(record.insufficient_telemetry, dict)
        assert isinstance(record.sequence_failure, dict)
        assert isinstance(record.baseline_failure, dict)
        assert isinstance(record.model_failure, dict)
        # spec-mandated FN diagnostics are all present
        assert {
            "missing_signal",
            "insufficient_telemetry",
            "sequence_failure",
            "baseline_failure",
            "model_failure",
        } <= set(record.to_log_dict())


# ---------------------------------------------------------------------- #
# Performance benchmarks
# ---------------------------------------------------------------------- #


class TestPerformanceBenchmarks:
    def test_all_three_execution_modes_benchmarked(self, attack_events):
        results = run_benchmarks(attack_events[:64])
        assert set(results) == {"batch", "streaming", "replay"}
        for mode, result in results.items():
            assert result.mode == mode
            assert result.n_events == 64
            assert result.events_processed >= 64
            assert result.events_per_second > 0
            assert result.avg_latency_ms > 0
            assert result.p95_latency_ms >= result.avg_latency_ms - 1e-9
            assert result.cpu_seconds >= 0
            assert result.peak_memory_mb > 0


# ---------------------------------------------------------------------- #
# Framework-free REST API
# ---------------------------------------------------------------------- #


class TestAPIIntegration:
    def test_analyze_endpoint_persists_and_reports(self, attack_events):
        repository = DestructionRepository()
        response = analyze(attack_events, repository=repository)
        assert response["events_accepted"] == 90
        assert response["sessions_built"] == 3
        assert response["findings_total"] == 3
        assert response["destructive_findings"] == 1
        assert response["threshold"] == ANALYZE_THRESHOLD
        assert len(response["findings"]) == 3
        for payload in response["findings"]:
            assert "contract" in payload
            assert "dashboard" in payload
        assert response["detector_versions"]
        assert repository.count_events() == 90

    def test_findings_endpoint(self, attack_events):
        repository = DestructionRepository()
        analyze(attack_events, repository=repository)
        response = list_findings(repository)
        assert response["count"] == 3
        assert all("finding_id" in finding for finding in response["findings"])

    def test_protection_profile_endpoint(self, attack_events):
        repository = DestructionRepository()
        analyze(attack_events, repository=repository)
        resource_id = attack_events[40].resource_id  # first attack resource
        response = get_protection_profile(repository, resource_id)
        assert response["resource_id"] == resource_id
        assert response["profile"]["resource_id"] == resource_id
        assert "business_criticality" in response["profile"]

    def test_destructive_session_endpoint(self, attack_events):
        repository = DestructionRepository()
        analyze(attack_events, repository=repository)
        session_id = list_findings(repository)["findings"][0]["session_id"]
        response = get_destructive_session(repository, session_id)
        assert response["session_id"] == session_id
        assert response["session"]["session_id"] == session_id

    def test_finding_explanation_endpoint(self, attack_events):
        repository = DestructionRepository()
        analyze(attack_events, repository=repository)
        findings = list_findings(repository)["findings"]
        destructive = max(findings, key=lambda finding: finding["risk_score"])
        response = get_finding_explanation(repository, destructive["finding_id"])
        assert response["finding_id"] == destructive["finding_id"]
        assert response["explanation"] is not None
        assert response["contract"]["finding_type"] == FINDING_TYPE
        dashboard = response["dashboard"]
        assert dashboard["potential_cloud_destructive_activity"] == FINDING_TYPE
        assert dashboard["risk_score"] >= HIGH_RISK_THRESHOLD
        assert dashboard["timeline"]
        assert dashboard["recommended_next_steps"]

    def test_unknown_ids_return_not_found_errors(self, attack_events):
        repository = DestructionRepository()
        analyze(attack_events, repository=repository)
        cases = (
            (get_protection_profile, {"resource_id": "no-such-resource"}),
            (get_destructive_session, {"session_id": "no-such-session"}),
            (get_finding_explanation, {"finding_id": "no-such-finding"}),
        )
        for handler, kwargs in cases:
            response = handler(repository, **kwargs)
            assert response["error"] == "not_found"


# ---------------------------------------------------------------------- #
# Independence gates
# ---------------------------------------------------------------------- #


class TestIndependenceGates:
    def test_reverse_context_never_triggers_destruction(self):
        """Reverse test: Credential Compromise = HIGH and Data
        Exfiltration = HIGH while destructive behavior is NORMAL
        must NOT generate a destruction finding. Algorithm #3 does
        not measure those signals, so they cannot move its score —
        here they are carried in the telemetry envelope itself."""
        benign = []
        for scenario in SCENARIOS:
            if scenario.expected_positive:
                continue
            for event in scenario.events(
                CORPUS_BASE
                + timedelta(hours=SCENARIO_SPACING_HOURS * scenario.number)
            ):
                benign.append(
                    event.model_copy(
                        update={
                            "request_parameters": {
                                "credential_compromise": "HIGH",
                                "data_exfiltration": "HIGH",
                            }
                        }
                    )
                )
        outcome = DestructionDetector().detect(benign)
        assert outcome.findings  # benign sessions still produce findings
        destructive = [
            finding
            for finding in outcome.findings
            if finding.risk_score >= THRESHOLD
        ]
        assert destructive == []

    def test_detector_has_no_external_finding_inputs(self):
        parameters = list(inspect.signature(DestructionDetector.detect).parameters)
        assert parameters == ["self", "events"]
        init_parameters = set(
            inspect.signature(DestructionDetector.__init__).parameters
        )
        assert not {"credential_compromise", "data_exfiltration"} & init_parameters

    def test_mandatory_independent_detection(self, attack_outcome):
        """Mandatory independence test: with Credential Compromise
        and Data Exfiltration detectors disabled (neither exists in
        this package — see the import gates below), the injected
        mass-modification + mass-deletion + version-deletion +
        backup/snapshot-deletion chain still generates a finding."""
        session = _attack_session(attack_outcome)
        finding = _finding_for(attack_outcome, session)
        assert finding.risk_score >= THRESHOLD
        assert finding.risk_score >= HIGH_RISK_THRESHOLD

    def test_no_imports_or_references_to_algorithms_1_and_2(self):
        forbidden = ("Aegivion_algo_1", "Aegivion_algo_2")
        violations = []
        for base in (_PACKAGE_ROOT, _INGESTION_ROOT):
            for path in sorted(base.rglob("*.py")):
                if "__pycache__" in path.parts:
                    continue
                source = path.read_text(encoding="utf-8")
                for node in ast.walk(ast.parse(source)):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name.startswith(forbidden):
                                violations.append(
                                    f"{path}: imports {alias.name}"
                                )
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        if node.module.startswith(forbidden):
                            violations.append(
                                f"{path}: imports {node.module}"
                            )
                for prefix in forbidden:
                    # allow the test files themselves to name
                    # the forbidden prefixes (mirrors
                    # test_independence.py's own gate)
                    if path.name in (
                        "test_part7_final.py",
                        "test_independence.py",
                    ):
                        continue
                    if prefix in source:
                        violations.append(f"{path}: mentions {prefix}")
        assert violations == []

    def test_importing_the_package_loads_no_sibling_algorithm(self):
        for name in list(sys.modules):
            if name.startswith(("Aegivion_algo_1", "Aegivion_algo_2")):
                del sys.modules[name]
        import importlib

        importlib.import_module("detection.cloud_destruction")
        loaded = [
            name
            for name in sys.modules
            if name.startswith(("Aegivion_algo_1", "Aegivion_algo_2"))
        ]
        assert loaded == []


# ---------------------------------------------------------------------- #
# Final acceptance test — the 17 mandated steps
# ---------------------------------------------------------------------- #


class TestFinalAcceptance:
    """The final acceptance test: a legitimate identity runs the
    full destruction kill chain while Algorithms #1 and #2 are
    disabled. Each numbered step's observable output is asserted
    from one ``detect()`` run, plus API exposure."""

    def test_normalization_round_trip(self, attack_events):
        """Step 1 (normalization): raw telemetry normalizes into
        canonical events; a canonical record round-trips through
        the normalizer unchanged."""
        source = attack_events[40]  # first attack-phase event
        record = {
            "event_id": source.event_id,
            "timestamp": source.timestamp.isoformat(),
            "provider": source.provider.value,
            "account_id": source.account_id,
            "region": source.region,
            "actor_id": source.actor_id,
            "actor_type": source.actor_type.value,
            "resource_id": source.resource_id,
            "resource_type": source.resource_type.value,
            "resource_arn": source.resource_arn,
            "action_category": source.action_category.value,
            "operation_type": (
                source.operation_type.value if source.operation_type else None
            ),
            "raw_action": source.raw_action,
            "business_criticality": (
                source.business_criticality.value
                if source.business_criticality
                else None
            ),
        }
        normalized = ResourceActivityNormalizer().normalize_generic(
            record, is_synthetic=True, generator="acceptance-test"
        )
        assert normalized.event_id == source.event_id
        assert normalized.actor_id == source.actor_id
        assert normalized.resource_id == source.resource_id
        assert normalized.action_category == source.action_category
        assert normalized.business_criticality == source.business_criticality

    def test_acceptance_chain_seventeen_steps(
        self, attack_events, attack_outcome
    ):
        session = _attack_session(attack_outcome)
        finding = _finding_for(attack_outcome, session)
        vector = _vector_for(attack_outcome, session)
        report = _report_for(attack_outcome, finding)
        explanation = _explanation_for(attack_outcome, finding)
        categories = _categories_for(attack_outcome, finding)

        # 1. normalize the telemetry — all events are canonical,
        #    provider-tagged events (round-trip proved above)
        assert all(isinstance(e, ResourceActivityEvent) for e in attack_events)
        assert all(e.provider and e.account_id and e.region for e in attack_events)

        # 2. build the activity session
        assert len(attack_outcome.sessions) == 3
        assert session.event_count == 50
        assert session.actor_id == "alice.admin"

        # 3. compare against resource baseline — every session has
        #    a feature vector; the two benign history sessions are
        #    the baseline the attack is measured against
        assert vector is not None
        assert vector.baseline_quality is not None
        for history in attack_outcome.sessions:
            if history.session_id != session.session_id:
                assert _vector_for(attack_outcome, history) is not None

        # 4. detect modification anomaly
        assert "MASS_MODIFICATION" in categories
        assert vector.modify_rate_deviation is not None
        assert vector.modify_rate_deviation.available

        # 5. detect deletion anomaly
        assert "MASS_DELETION" in categories

        # 6. detect version destruction
        assert "VERSION_DESTRUCTION" in categories
        assert session.version_deletions == 8

        # 7. detect recovery destruction
        assert "RECOVERY_DESTRUCTION" in categories
        assert session.snapshot_deletions == 4
        assert session.backup_deletions == 4

        # 8. detect protection degradation
        assert "PROTECTION_DEGRADATION" in categories
        assert session.protection_changes == 2

        # 9. detect destructive sequence
        assert attack_outcome.sequence_scores[session.session_id] > 0.5
        assert "COMPOUND_DESTRUCTIVE_ACTIVITY" in categories
        assert "MULTI_RESOURCE_DESTRUCTION" in categories
        # every observed category is valid detector vocabulary
        assert categories <= {category.value for category in DestructiveBehaviorCategory}

        # 10. calculate ML anomaly
        assert attack_outcome.anomaly_scores[session.session_id] >= 0.9

        # 11. calculate destruction risk
        assert finding.risk_score >= HIGH_RISK_THRESHOLD

        # 12. calculate confidence
        assert 0.0 < finding.confidence_score < 1.0
        assert finding.severity.value == "critical"

        # 13. run ARDE
        assert report is not None
        assert len(report.checks) == 10
        assert report.overall.value in ("pass", "warn", "fail")

        # 14. generate an independent finding with honest wording
        attack_phase_events = [
            event
            for event in attack_events
            if not event.event_id.startswith("ac-h")
        ]
        contract = build_finding_contract(
            finding,
            session,
            explanation=explanation,
            report=report,
            vector=vector,
            events=attack_phase_events,
        )
        assert contract["finding_type"] == FINDING_TYPE
        assert FINDING_LABEL == "Potential cloud destructive activity"
        assert contract["severity"] == "critical"
        assert contract["risk_score"] >= HIGH_RISK_THRESHOLD
        assert 0.0 < contract["confidence"] < 1.0
        assert 0.0 <= contract["robustness_score"] <= 1.0
        assert contract["actor"] == "alice.admin"
        assert contract["session"] == session.session_id
        assert contract["resources_affected"]["count"] > 0
        assert contract["modifications"] > 0
        assert contract["deletions"] > 0
        assert contract["version_deletions"] == 8
        assert contract["snapshot_deletions"] == 4
        assert contract["backup_deletions"] == 4
        assert contract["protection_changes"] == 2
        assert contract["business_criticality"] == "critical"
        assert contract["recoverability"]["status"] in (
            "intact",
            "degraded",
            "destroyed",
            "unknown",
        )
        assert contract["signals"]
        assert contract["supporting_evidence"]
        assert isinstance(contract["contradicting_evidence"], list)
        assert contract["baseline_quality"]
        assert contract["telemetry_completeness"]
        assert contract["model_version"]
        assert contract["feature_version"]
        assert contract["scoring_version"]
        assert contract["rule_version"]
        assert contract["recommended_next_steps"]
        # accuracy integrity: potential activity, never confirmed
        # ransomware and never a perfection claim
        serialized = json.dumps(contract).lower()
        assert "ransomware" not in serialized
        assert "confirmed" not in serialized
        assert "100%" not in serialized

        # 15. preserve evidence — events, sessions, findings (with
        #     explanations and contracts) survive a persistence
        #     round-trip
        repository = DestructionRepository()
        repository.save_events(attack_events)
        repository.save_sessions(attack_outcome.sessions)
        repository.save_findings(
            attack_outcome.findings,
            explanations=attack_outcome.explanations,
            contracts=[
                build_finding_contract(
                    candidate,
                    next(
                        s
                        for s in attack_outcome.sessions
                        if s.session_id == candidate.session_id
                    ),
                )
                for candidate in attack_outcome.findings
            ],
        )
        assert repository.count_events() == 90
        assert len(repository.list_sessions()) == 3
        assert len(repository.list_findings()) == 3
        persisted = repository.get_finding(finding.finding_id)
        assert persisted is not None
        assert persisted.risk_score == finding.risk_score
        assert persisted.session_id == finding.session_id

        # 16. expose the finding through the API
        api_repository = DestructionRepository()
        response = analyze(attack_events, repository=api_repository)
        assert response["destructive_findings"] == 1
        destructive_payload = max(
            response["findings"], key=lambda payload: payload["risk_score"]
        )
        assert destructive_payload["contract"]["finding_type"] == FINDING_TYPE
        assert destructive_payload["contract"]["risk_score"] >= HIGH_RISK_THRESHOLD
        assert destructive_payload["dashboard"]["risk_score"] >= HIGH_RISK_THRESHOLD
        explanation_response = get_finding_explanation(
            api_repository, destructive_payload["finding_id"]
        )
        assert explanation_response["dashboard"]["timeline"]
        assert explanation_response["dashboard"]["recommended_next_steps"]

        # 17. remain completely independent from Algorithms #1
        #     and #2 — no sibling algorithm is loaded, and the
        #     package source never references them (the static
        #     gates in TestIndependenceGates enforce this
        #     permanently; here the runtime state is checked)
        assert not any(
            name.startswith(("Aegivion_algo_1", "Aegivion_algo_2"))
            for name in sys.modules
        )
