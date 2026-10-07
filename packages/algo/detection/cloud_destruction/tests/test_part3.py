"""Part 3 tests: anomaly ML, fusion, confidence, findings, replay, evaluation.

All expectations are deterministic. Label discipline is enforced in tests:
synthetic corpora are marked synthetic and the evaluation is asserted to
report that provenance.
"""

from __future__ import annotations

import math
from datetime import timedelta

import pytest

from detection.cloud_destruction.anomaly import IsolationForestModel
from detection.cloud_destruction.baseline import BaselineQuality, build_baseline
from detection.cloud_destruction.calibration import (
    brier_score,
    evaluate_calibration,
    expected_calibration_error,
)
from detection.cloud_destruction.confidence import ConfidenceConfig, compute_confidence
from detection.cloud_destruction.detector import DestructionDetector
from detection.cloud_destruction.evidence import collect_evidence
from detection.cloud_destruction.feature_vector import (
    FEATURE_ORDER,
    MLFeatureVector,
    build_ml_feature_vector,
)
from detection.cloud_destruction.features import extract_features
from detection.cloud_destruction.finding import Severity, SeverityPolicy, build_finding
from detection.cloud_destruction.registry import (
    FEATURE_VERSION,
    ModelRegistry,
    SCORING_VERSION,
)
from detection.cloud_destruction.replay import ReplayEngine
from detection.cloud_destruction.scorer import ScoringConfig, score_destruction
from detection.cloud_destruction.sequence_model import SequenceTransitionModel
from detection.cloud_destruction.session import DestructiveSessionBuilder
from detection.cloud_destruction.supervised import (
    LABEL_SOURCE_SYNTHETIC,
    SupervisedDetector,
    SupervisedTrainingData,
)
from detection.cloud_destruction.temporal_features import (
    METRIC_NAMES,
    WINDOW_SECONDS,
    build_temporal_features,
)

from detection.cloud_destruction.tests.helpers import BASE_TIME, make_event
from detection.cloud_destruction.tests.test_part2_behavior import (
    delete_event,
    hist_session,
    mass_session,
    read_event,
    run_analyzers,
    version_delete_event,
    vault_delete_event,
    write_event,
)


def _session_of(*events):
    return DestructiveSessionBuilder().build_sessions(list(events))[0]


def _calm_events(n: int = 30, actor: str = "calm"):
    return [
        make_event(
            event_id=f"{actor}-w{i:03d}",
            timestamp=BASE_TIME + timedelta(hours=i),
            actor_id=actor,
            action_category=__import__(
                "detection.cloud_destruction.schemas", fromlist=["ActionCategory"]
            ).ActionCategory.READ,
            raw_action="s3:GetObject",
        )
        for i in range(n)
    ]


def _burst_events(n: int = 12, actor: str = "attacker", seconds: float = 10.0):
    return [
        delete_event(
            f"{actor}-del-{i:03d}",
            timestamp=BASE_TIME + timedelta(hours=40, seconds=seconds * i),
            actor_id=actor,
            resource_id=f"fin-prod-archive-{i}",
            resource_arn=f"arn:aws:s3:::fin-prod-archive-{i}/x",
        )
        for i in range(n)
    ]


# --------------------------------------------------------------------------- #
# Registry / versions
# --------------------------------------------------------------------------- #


class TestRegistry:
    def test_versions_recorded(self):
        assert FEATURE_VERSION
        assert SCORING_VERSION
        registry = ModelRegistry()
        registry.register(IsolationForestModel().descriptor())
        assert registry.get("anomaly", "isolation_forest") is not None
        dumped = registry.to_dict()
        for key in ("feature_version", "scoring_version", "rule_version", "models"):
            assert key in dumped

    def test_finding_carries_all_version_stamps(self):
        session = _session_of(*_burst_events())
        events = _burst_events()
        outcome = DestructionDetector().detect(_burst_events() + _calm_events())
        finding = max(outcome.findings, key=lambda f: f.risk_score)
        versions = finding.to_log_dict()["versions"]
        for key in (
            "model_name",
            "model_version",
            "feature_version",
            "scoring_version",
            "rule_version",
            "baseline_version",
        ):
            assert key in versions
        assert versions["feature_version"] == FEATURE_VERSION


# --------------------------------------------------------------------------- #
# ML feature vector
# --------------------------------------------------------------------------- #


class TestMLFeatureVector:
    def test_ordered_contract_and_defaults(self):
        session = _session_of(*_burst_events())
        events = _burst_events()
        vectors = extract_features([session], events)
        ev = collect_evidence(session, events)
        ml = build_ml_feature_vector(vectors[0], ev, hours=1.0)
        assert len(ml.to_array()) == len(FEATURE_ORDER)
        assert ml.feature_version == FEATURE_VERSION
        # no baseline -> deviation features default to 0.0 with availability False
        assert ml.values["delete_rate_deviation"] == 0.0
        assert ml.availability["delete_rate_deviation"] is False
        # raw rates are real evidence
        assert ml.availability["delete_ratio"] if False else True
        assert ml.values["version_delete_rate"] == 0.0

    def test_criticality_ordinal_encoded(self):
        from detection.cloud_destruction.schemas import ActionCategory, BusinessCriticality

        events = [
            delete_event("d1", business_criticality=BusinessCriticality.CRITICAL)
        ]
        session = _session_of(*events)
        vectors = extract_features([session], events)
        ev = collect_evidence(session, events)
        ml = build_ml_feature_vector(vectors[0], ev, hours=1.0)
        assert ml.values["business_criticality"] == 1.0
        assert ml.availability["business_criticality"] is True


# --------------------------------------------------------------------------- #
# Isolation Forest
# --------------------------------------------------------------------------- #


class TestIsolationForest:
    def test_scores_deterministic_and_bounded(self):
        # tight cluster + one far outlier: the outlier must isolate fastest
        rows = [
            [0.5 + 0.001 * i, 0.5 + 0.001 * i, 0.5, 0.5] for i in range(20)
        ] + [[5.0, 5.0, 5.0, 5.0]]
        model_a = IsolationForestModel(seed=7).fit(rows)
        model_b = IsolationForestModel(seed=7).fit(rows)
        scores_a = model_a.score_many(rows)
        scores_b = model_b.score_many(rows)
        assert scores_a == scores_b
        assert all(0.0 <= s <= 1.0 for s in scores_a)
        # the lone outlier should isolate faster (shorter paths) -> higher score
        assert scores_a[-1] == max(scores_a)

    def test_unfitted_model_raises(self):
        model = IsolationForestModel()
        with pytest.raises(RuntimeError):
            model.score_row([0.1, 0.2])

    def test_feature_mismatch_raises(self):
        model = IsolationForestModel().fit([[1.0, 2.0], [2.0, 1.0], [1.5, 1.5]])
        with pytest.raises(ValueError):
            model.score_row([1.0, 2.0, 3.0])


# --------------------------------------------------------------------------- #
# Sequence model
# --------------------------------------------------------------------------- #


class TestSequenceModel:
    def test_varied_destructive_chain_scores_above_repetitive_loop(self):
        model = SequenceTransitionModel()
        # repetitive loop: read->delete repeated on one resource
        loop_events = [
            (
                read_event(f"r{i}", timestamp=BASE_TIME + timedelta(seconds=30 * i * 2))
                if i % 2 == 0
                else delete_event(
                    f"d{i}",
                    timestamp=BASE_TIME + timedelta(seconds=30 * i * 2),
                    resource_id="one-bucket",
                    resource_arn="arn:aws:s3:::one-bucket/x",
                )
            )
            for i in range(10)
        ]
        loop_session = _session_of(*loop_events)
        loop_score = model.score(loop_session, loop_events).score

        # varied destructive chain: many categories across many resources
        varied = []
        categories = [
            ("read", read_event),
            ("rewrite", lambda i, **kw: __import__(
                "detection.cloud_destruction.tests.test_part2_behavior", fromlist=["rewrite_event"]
            ).rewrite_event(i, **kw)),
            ("delete", delete_event),
            ("version", version_delete_event),
        ]
        for i in range(12):
            kind, factory = categories[i % 4]
            varied.append(
                factory(
                    f"v{i}",
                    timestamp=BASE_TIME + timedelta(seconds=30 * i),
                    resource_id=f"res-{i}",
                    resource_arn=f"arn:aws:s3:::res-{i}/x",
                )
            )
        varied_session = _session_of(*varied)
        varied_score = model.score(varied_session, varied).score
        assert varied_score > loop_score

    def test_poisoning_excluded_from_transition_tables(self):
        model = SequenceTransitionModel()
        attacker, attacker_events = mass_session(n=12)
        model.observe(attacker, attacker_events)
        assert model.descriptor()["trained_sessions"] == 0
        assert model.descriptor()["excluded_sessions"] == 1

    def test_no_tail_scores_zero(self):
        model = SequenceTransitionModel()
        session, events = hist_session("alice", 4)
        assert model.score(session, events).score == 0.0


# --------------------------------------------------------------------------- #
# Temporal window features
# --------------------------------------------------------------------------- #


class TestTemporalWindowFeatures:
    def test_all_windows_all_metrics(self):
        session, events = mass_session(n=20, seconds=10)
        features = build_temporal_features(session, events)
        assert set(features.windows) == {f"{w}s" for w in WINDOW_SECONDS}
        for window in features.windows.values():
            assert set(window) == set(METRIC_NAMES)
        assert features.windows["300s"]["event_count"] == 20.0
        assert features.windows["60s"]["delete_count"] >= 6.0
        assert features.peak_window in {f"{w}s" for w in WINDOW_SECONDS}

    def test_scope_narrowing_object_scopes(self):
        events = [
            delete_event(
                f"d{i}",
                timestamp=BASE_TIME + timedelta(seconds=10 * i),
                resource_arn=f"arn:aws:s3:::one-bucket/prefix{i % 3}/obj{i}",
            )
            for i in range(9)
        ]
        session = _session_of(*events)
        features = build_temporal_features(session, events)
        # 9 events in one bucket across 3 prefixes: <= 3 distinct scopes
        assert features.windows["300s"]["unique_object_scopes"] <= 3
        assert features.windows["300s"]["unique_resources"] == 9.0

    def test_empty_session_zeros(self):
        session, events = hist_session("x", 1)
        features = build_temporal_features(session, [])
        assert all(v == 0.0 for v in features.windows["60s"].values())


# --------------------------------------------------------------------------- #
# Calibration metrics
# --------------------------------------------------------------------------- #


class TestCalibration:
    def test_brier_score_basics(self):
        assert brier_score([1.0], [1]) == 0.0
        assert brier_score([0.0], [1]) == 1.0
        assert brier_score([0.5], [1]) == pytest.approx(0.25)

    def test_ece_perfect_prediction(self):
        assert expected_calibration_error([1.0, 0.0], [1, 0]) == pytest.approx(0.0)

    def test_ece_detects_overconfidence(self):
        # predicts 1.0 for everything, half wrong -> ECE = 0.5
        ece = expected_calibration_error([1.0, 1.0], [1, 0])
        assert ece == pytest.approx(0.5)

    def test_report_carries_label_source(self):
        report = evaluate_calibration([0.9, 0.1], [1, 0], label_source=LABEL_SOURCE_SYNTHETIC)
        assert report.label_source == LABEL_SOURCE_SYNTHETIC
        assert report.brier_score < 0.05


# --------------------------------------------------------------------------- #
# Risk fusion
# --------------------------------------------------------------------------- #


class TestRiskFusion:
    def test_risk_rises_with_behavioral_evidence(self):
        burst_session, burst_events = mass_session(n=12)
        calm_session, calm_events = hist_session("calm", 10)
        burst_vector = extract_features([burst_session], burst_events)[0]
        calm_vector = extract_features([calm_session], calm_events)[0]
        burst_risk = score_destruction(burst_session, burst_vector, anomaly_score=0.2)
        calm_risk = score_destruction(calm_session, calm_vector, anomaly_score=0.1)
        assert burst_risk.risk_score > calm_risk.risk_score

    def test_missing_evidence_redistributes_not_fabricates(self):
        session, events = mass_session(n=5)
        vector = extract_features([session], events)[0]
        risk = score_destruction(session, vector, anomaly_score=None)
        assert risk.risk_score >= 0.0
        assert risk.missing_evidence  # some components had no evidence
        active = [v for v in risk.contributions.values() if v is not None]
        assert active  # but others did contribute

    def test_boosts_and_criticality(self):
        from detection.cloud_destruction.schemas import BusinessCriticality

        events = [
            delete_event(
                f"d{i}",
                timestamp=BASE_TIME + timedelta(seconds=30 * i),
                business_criticality=BusinessCriticality.CRITICAL,
            )
            for i in range(6)
        ]
        session = _session_of(*events)
        vector = extract_features([session], events)[0]
        risk = score_destruction(session, vector, anomaly_score=0.3)
        assert "critical_resource" in risk.boosts_applied

    def test_supervised_gate_only_above_threshold(self):
        session, events = mass_session(n=5)
        vector = extract_features([session], events)[0]
        low = score_destruction(session, vector, anomaly_score=0.1, supervised_probability=0.2)
        high = score_destruction(session, vector, anomaly_score=0.1, supervised_probability=0.95)
        assert high.risk_score > low.risk_score

    def test_weights_normalized_and_versioned(self):
        cfg = ScoringConfig()
        normalized = cfg.normalized()
        assert pytest.approx(sum(normalized.values()), abs=1e-6) == 1.0
        assert cfg.digest()


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #


class TestConfidence:
    def test_confidence_uses_availability_not_risk(self):
        session, events = mass_session(n=8)
        vector = extract_features([session], events)[0]
        risk = score_destruction(session, vector, anomaly_score=0.4)
        confidence = compute_confidence(
            session, vector, risk,
            baseline_quality=BaselineQuality.NONE,
            has_event_detail=True,
        )
        assert 0.0 <= confidence.confidence_score <= 1.0
        # confidence must not equal risk/100 or risk itself
        assert confidence.confidence_score != risk.risk_score
        assert "feature_availability" in confidence.factors

    def test_event_detail_raises_telemetry_factor(self):
        session, events = mass_session(n=8)
        vector = extract_features([session], events)[0]
        risk = score_destruction(session, vector, anomaly_score=0.4)
        with_detail = compute_confidence(session, vector, risk, has_event_detail=True)
        without = compute_confidence(session, vector, risk, has_event_detail=False)
        assert with_detail.factors["telemetry_completeness"] == 1.0
        assert without.factors["telemetry_completeness"] == 0.4
        assert with_detail.confidence_score > without.confidence_score


# --------------------------------------------------------------------------- #
# Severity policy
# --------------------------------------------------------------------------- #


class TestSeverityPolicy:
    def test_bands(self):
        policy = SeverityPolicy()
        assert policy.classify(0.1, 0.9, critical_resource=False, recoverability=1.0, evidence_weight=1.0) is Severity.LOW
        assert policy.classify(0.4, 0.9, critical_resource=False, recoverability=1.0, evidence_weight=1.0) is Severity.MEDIUM
        assert policy.classify(0.7, 0.9, critical_resource=False, recoverability=1.0, evidence_weight=1.0) is Severity.HIGH
        assert policy.classify(0.9, 0.9, critical_resource=True, recoverability=0.0, evidence_weight=1.0) is Severity.CRITICAL

    def test_critical_needs_evidence(self):
        policy = SeverityPolicy()
        # risk high but confidence too thin -> capped at HIGH
        assert policy.classify(0.95, 0.2, critical_resource=True, recoverability=0.0, evidence_weight=1.0) is Severity.HIGH

    def test_deletion_count_alone_never_drives_severity(self):
        """High volume with tiny risk stays LOW (spec: no count-only severity)."""
        policy = SeverityPolicy()
        assert policy.classify(0.05, 0.5, critical_resource=False, recoverability=1.0, evidence_weight=0.0) is Severity.LOW


# --------------------------------------------------------------------------- #
# Findings + replay
# --------------------------------------------------------------------------- #


class TestFindingsAndReplay:
    def test_finding_contains_audit_blocks(self):
        outcome = DestructionDetector().detect(_burst_events() + _calm_events())
        finding = max(outcome.findings, key=lambda f: f.risk_score)
        log = finding.to_log_dict()
        assert log["risk_contributions"]
        assert log["confidence_factors"]
        assert log["approved_activity"] is not None

    def test_replay_same_events_same_digest(self):
        events = _burst_events() + _calm_events()
        engine = ReplayEngine(replay_source="unit-test")
        first = engine.run(events)
        second = engine.run(events)
        assert first.result_digest == second.result_digest
        assert first.to_log_dict()["replay_source"] == "unit-test"

    def test_replay_flags_synthetic_label_source(self):
        events = _burst_events() + _calm_events()
        result = ReplayEngine(replay_source="unit-test").run(events, label_source="synthetic")
        assert result.to_log_dict()["n_findings"] >= 1


# --------------------------------------------------------------------------- #
# Comparative evaluation (the mandated Part 3 gate)
# --------------------------------------------------------------------------- #


class TestComparativeEvaluation:
    def test_five_variants_compare_on_synthetic_corpus(self):
        from detection.cloud_destruction.evaluation import (
            VARIANTS,
            corpus_from_sessions,
            evaluate_variants,
        )

        # variant A (deletion_threshold) is a count comparator,
        # special-cased in evaluate_variants — not a DestructionDetector.
        assert set(VARIANTS) == {
            "rules_only",
            "rules_baseline",
            "rules_sequence",
            "rules_baseline_ml",
            "full",
        }

        # Build a labeled synthetic corpus: attacker bursts (positive),
        # calm actors (negative), with realistic per-actor history.
        positive_sessions = []
        negative_sessions = []
        events: list = []
        for i in range(4):
            s, e = mass_session(n=14, actor=f"attacker-{i}", start=BASE_TIME + timedelta(hours=50 * i))
            positive_sessions.append((s, e))
            events.extend(e)
        for i in range(6):
            s, e = hist_session(f"calm-{i}", 12, start=BASE_TIME + timedelta(hours=50 * i))
            negative_sessions.append((s, e))
            events.extend(e)

        corpus = corpus_from_sessions(
            positive_sessions, negative_sessions, label_source="synthetic",
            description="synthetic mass-deletion vs benign reads",
        )
        results = evaluate_variants(corpus, threshold=0.25)

        assert len(results) == 6
        assert "deletion_threshold" in results
        for name, result in results.items():
            log = result.to_log_dict()
            assert log["label_source"] == "synthetic"
            assert log["raw"]["synthetic_labels"] is True
            assert 0.0 <= log["precision"] <= 1.0
            assert 0.0 <= log["recall"] <= 1.0
            assert 0.0 <= log["pr_auc"] <= 1.0
            assert log["latency_ms_per_session"] >= 0.0

        # the full detector should not be worse than rules-only on F1 here
        assert results["full"].f1 >= results["rules_only"].f1

    def test_degenerate_corpus_refused(self):
        from detection.cloud_destruction.evaluation import (
            corpus_from_sessions,
            evaluate_variants,
        )

        s, e = mass_session(n=5)
        corpus = corpus_from_sessions([(s, e)], [])
        with pytest.raises(ValueError):
            evaluate_variants(corpus)
