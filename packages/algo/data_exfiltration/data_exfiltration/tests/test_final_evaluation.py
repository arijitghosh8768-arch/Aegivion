"""Final-stage evaluation tests (Part 5): metrics, tuning, errors, artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from algo.data_exfiltration.data_exfiltration.evaluation.ablation import (
    ABLATABLE_COMPONENTS,
    ablate_features,
    ablate_stack,
)
from algo.data_exfiltration.data_exfiltration.evaluation.dataset import LabeledRecord
from algo.data_exfiltration.data_exfiltration.evaluation.error_analysis import analyze_errors
from algo.data_exfiltration.data_exfiltration.evaluation.metrics import (
    false_negative_rate,
    full_metrics,
    precision_at_high_risk,
    recall_at_fixed_fpr,
)
from algo.data_exfiltration.data_exfiltration.evaluation.runner import evaluate
from algo.data_exfiltration.data_exfiltration.evaluation.tuning import (
    run_threshold_tuning,
    split_records,
    threshold_curve,
    tune_threshold,
    verify_split_integrity,
)
from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    AvailableFeature,
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_ARTIFACT_DIR = _PROJECT_ROOT / "evaluation_artifacts"


def _fset(session_id: str, risk: float) -> BehavioralFeatureSet:
    fset = BehavioralFeatureSet(
        subject_id="actor", session_id=session_id, actor_id="actor",
        computed_at_epoch_ms=1000.0, baseline_quality=0.9, baseline_scope_used="personal",
    )

    def _f(v: float) -> AvailableFeature:
        return AvailableFeature(value=v, availability=FeatureAvailability.OBSERVED)

    fset.volume_score = _f(risk)
    fset.object_count_score = _f(risk * 0.8)
    fset.request_rate_score = _f(risk * 0.7)
    fset.destination_score = _f(risk * 0.9)
    fset.access_pattern_score = _f(risk * 0.6)
    fset.sensitivity_score = _f(0.3 if risk < 0.5 else 0.85)
    fset.time_score = _f(risk * 0.4)
    fset.actor_resource_score = _f(risk * 0.5)
    fset.egress_score = _f(risk * 0.8)
    return fset.finalize()


def _records(n: int = 60) -> list[LabeledRecord]:
    recs: list[LabeledRecord] = []
    for i in range(n):
        label = i % 2
        session = DataAccessSession(
            session_id=f"s{i}",
            actor_id="actor",
            start_time_epoch_ms=1000.0 + i,
            end_time_epoch_ms=1010.0 + i,
            event_count=2,
        )
        session.session_features["_behavioral_feature_set"] = _fset(
            f"s{i}", 0.85 if label else 0.05
        )
        recs.append(
            LabeledRecord(session=session, finding=None, label=label, scenario="synthetic", instance=i)
        )
    return recs


class TestMetrics:
    def test_full_metrics_block_complete(self) -> None:
        scores = [0.9, 0.8, 0.2, 0.1]
        labels = [1, 1, 0, 0]
        m = full_metrics(scores, labels, threshold=0.5)
        for key in (
            "precision", "recall", "f1", "false_positive_rate", "false_negative_rate",
            "pr_auc", "roc_auc", "precision_at_high_risk", "recall_at_fixed_fpr",
        ):
            assert key in m, key
        assert m["precision"] == 1.0 and m["recall"] == 1.0
        assert m["false_positive_rate"] == 0.0

    def test_false_negative_rate(self) -> None:
        assert false_negative_rate([1, 1, 0], [1, 0, 0]) == 0.5
        assert false_negative_rate([0, 0], [0, 0]) == 0.0

    def test_precision_at_high_risk_none_when_band_empty(self) -> None:
        assert precision_at_high_risk([0.1, 0.2], [0, 1], threshold=0.7) is None
        assert precision_at_high_risk([0.9, 0.8], [1, 0], threshold=0.7) == 0.5

    def test_recall_at_fixed_fpr(self) -> None:
        # one clean separation point exists under a 0-FPR cap
        value = recall_at_fixed_fpr([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0], max_fpr=0.0)
        assert value == 1.0


class TestThresholdTuning:
    def test_curve_and_selection(self) -> None:
        recs = _records()
        # score with the stack (volume alone is not the fused risk)
        stack = ScoringStack(variant="B")
        scored = [stack.score(r.session.session_features["_behavioral_feature_set"]) for r in recs]
        labels = [r.label for r in recs]
        curve = threshold_curve([s.risk_score for s in scored], labels)
        assert curve and all(0.05 <= p.threshold <= 0.99 for p in curve)
        selection = tune_threshold([s.risk_score for s in scored], labels, metric="f1")
        assert 0.05 <= selection.threshold <= 0.99
        assert selection.validation_score is not None
        assert selection.constraints["satisfied"] is True

    def test_unsatisfiable_constraint_falls_back_to_default(self) -> None:
        selection = tune_threshold([0.1, 0.2], [0, 0], metric="f1", min_precision=1.0)
        assert selection.threshold == 0.5
        assert selection.constraints["satisfied"] is False

    def test_split_integrity_and_chronology(self) -> None:
        recs = _records(60)
        split, temporal = split_records(recs)
        report = verify_split_integrity(temporal)
        assert report["disjoint"] is True
        assert report["chronological"] is True
        assert report["counts"]["train"] + report["counts"]["validation"] + report["counts"]["test"] == 60

    def test_end_to_end_selection_on_validation_only(self) -> None:
        recs = _records(80)
        result = run_threshold_tuning(
            recs, ScoringStack(variant="B"),
            proportions={"train": 0.5, "validation": 0.25, "test": 0.25},
        )
        assert result["split_integrity"]["disjoint"] is True
        assert result["selection"]["data_used"].startswith("validation")
        assert result["test_metrics_at_selected"]["threshold"] == result["selection"]["threshold"]
        assert result["test_metrics_at_default"]["threshold"] == 0.5


class TestErrorAnalysis:
    def test_fp_and_fn_records(self) -> None:
        recs = _records(4)
        stack = ScoringStack(variant="B")
        scored = {r.session_id: stack.score(r.session.session_features["_behavioral_feature_set"]) for r in recs}
        # s0 is quiet (label 0 -> risk low) and s1 is loud (label 1 -> risk high).
        # Flip the ground truth to manufacture one FN and one FP.
        recs[0].label = 1  # quiet session labelled positive -> FN
        recs[1].label = 0  # loud session labelled negative -> FP
        report = analyze_errors(
            recs, scored, threshold=0.5,
            arde_by_session={"s1": "REVIEW_REQUIRED"},
            robustness_by_session={"s1": 0.2},
        )
        assert report.false_positives
        assert report.false_positives[0].reason
        assert report.false_positives[0].arde_result == "REVIEW_REQUIRED"
        assert report.false_negatives
        assert report.false_negatives[0].missing_signal


class TestAblation:
    def test_components_cover_the_contract(self) -> None:
        for component in (
            "volume", "destination", "sensitivity", "access_pattern",
            "time", "network_egress", "ml", "arde",
        ):
            assert component in ABLATABLE_COMPONENTS

    def test_ablate_features_marks_unavailable(self) -> None:
        fset = _fset("s1", 0.9)
        ablated = ablate_features(fset, "destination")
        assert ablated.destination_score.value is None
        assert ablated.destination_score.availability is FeatureAvailability.UNAVAILABLE
        # volume untouched
        assert ablated.volume_score.value == fset.volume_score.value

    def test_ablate_stack_removes_ml(self) -> None:
        stack = ScoringStack(variant="C", anomaly_model=object())
        assert ablate_stack(stack, "ml").anomaly_model is None
        assert ablate_stack(stack, "volume").anomaly_model is stack.anomaly_model


class TestEvaluationDeterminism:
    def test_two_runs_agree(self) -> None:
        first = evaluate(per_family=2)
        second = evaluate(per_family=2)
        assert (
            first["variants"]["E"]["metrics"]["f1"]
            == second["variants"]["E"]["metrics"]["f1"]
        )
        assert first["ablation"] == second["ablation"]
        assert first["threshold_tuning"] == second["threshold_tuning"]

    def test_committed_final_metrics_match_fresh_run(self) -> None:
        path = _ARTIFACT_DIR / "final_metrics.json"
        if not path.exists():
            pytest.skip("final artifacts not generated")
        committed = json.loads(path.read_text(encoding="utf-8"))
        fresh = evaluate(per_family=6)
        for name, result in fresh["variants"].items():
            stored = committed["variants"][name]
            assert result["metrics"]["f1"] == stored["f1"], f"{name} F1 drifted"
            assert result["metrics"]["recall"] == stored["recall"]
            assert result["metrics"]["false_positive_rate"] == stored["false_positive_rate"]

    def test_no_variant_claims_perfect_detection(self) -> None:
        path = _ARTIFACT_DIR / "final_metrics.json"
        if not path.exists():
            report = evaluate(per_family=6)
            committed = {k: v["metrics"] for k, v in report["variants"].items()}
        else:
            committed = json.loads(path.read_text(encoding="utf-8"))["variants"]
        for name, metrics in committed.items():
            assert metrics["recall"] < 1.0, f"{name} claims perfect recall"
            assert metrics["precision"] < 1.0, f"{name} claims perfect precision"


class TestArtifacts:
    def test_all_final_artifacts_present_and_marked_synthetic(self) -> None:
        expected = {
            "final_metrics.json", "final_ablation.json", "final_error_analysis.json",
            "final_arde_impact.json", "final_threshold_tuning.json", "final_performance.json",
        }
        if not _ARTIFACT_DIR.exists():
            pytest.skip("artifacts directory absent")
        present = {p.name for p in _ARTIFACT_DIR.glob("final_*.json")}
        missing = expected - present
        assert not missing, missing
        for name in sorted(expected):
            payload = json.loads((_ARTIFACT_DIR / name).read_text(encoding="utf-8"))
            assert payload.get("synthetic") is True, name

    def test_performance_artifact_is_labelled_a_measurement(self) -> None:
        path = _ARTIFACT_DIR / "final_performance.json"
        if not path.exists():
            pytest.skip("performance artifact not generated")
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert "not a service-level guarantee" in payload["note"]
        assert payload["batch"]["events_per_second"] >= 0
        assert payload["streaming"]["events_per_second"] >= 0
