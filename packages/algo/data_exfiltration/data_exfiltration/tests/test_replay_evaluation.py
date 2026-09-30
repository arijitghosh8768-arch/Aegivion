"""Replay mode, temporal splits, evaluation harness, and determinism tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    AvailableFeature,
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.confidence_engine import FindingConfidenceCalibrator
from algo.data_exfiltration.data_exfiltration.ml.evaluation import (
    EvaluationDataset,
    EvaluationHarness,
    classification_metrics,
    pr_auc,
    roc_curve,
)
from algo.data_exfiltration.data_exfiltration.ml.fusion import FusionWeights
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack
from algo.data_exfiltration.data_exfiltration.ml.replay import fit_isolation_forest, temporal_split
from algo.data_exfiltration.data_exfiltration.ml.versioning import ModelVersionInfo


def _fset(session_id: str, ts: float, risk: float, quality: float = 0.9) -> BehavioralFeatureSet:
    fset = BehavioralFeatureSet(
        subject_id="actor",
        session_id=session_id,
        actor_id="actor",
        computed_at_epoch_ms=ts,
        baseline_quality=quality,
        baseline_scope_used="personal",
    )
    def _f(v: float) -> AvailableFeature:
        return AvailableFeature(value=v, availability=FeatureAvailability.OBSERVED)
    fset.volume_score = _f(risk)
    fset.object_count_score = _f(min(1.0, risk * 0.8))
    fset.request_rate_score = _f(min(1.0, risk * 0.7))
    fset.destination_score = _f(min(1.0, risk * 0.9))
    fset.access_pattern_score = _f(min(1.0, risk * 0.6))
    fset.sensitivity_score = _f(0.3 if risk < 0.5 else 0.8)
    fset.time_score = _f(min(1.0, risk * 0.4))
    fset.actor_resource_score = _f(min(1.0, risk * 0.5))
    fset.egress_score = _f(min(1.0, risk * 0.8))
    # attach a deterministic feature vector for IF training/scoring
    fset.session_features["feature_vector"] = [
        risk, risk * 0.8, risk * 0.7, risk * 0.6, risk * 0.9, 0.1, 0.1, 0.1, 0.1,
        risk * 0.6, risk * 0.5, risk * 0.4, risk * 0.5, 0.3, 0.5, risk * 0.8, 0.1,
    ]
    return fset.finalize()


def _dataset(n_normal: int = 60, n_attack: int = 20) -> EvaluationDataset:
    features, labels = [], []
    ts = 1_700_000_000_000
    # interleave chronologically: attacks appear throughout, evaluated on test period
    for i in range(n_normal + n_attack):
        is_attack = (i % 4 == 3) and i >= 8  # every 4th session from index 8
        risk = 0.9 if is_attack else 0.1 + (i % 5) * 0.02
        features.append(_fset(f"s-{i}", ts + i * 3_600_000.0, risk))
        labels.append(1 if is_attack else 0)
    return EvaluationDataset(features=features, labels=labels, synthetic=True, source="unit_test")


class TestTemporalSplit:
    def test_no_future_in_training(self) -> None:
        items = _dataset().features
        split = temporal_split(items)
        assert split.train and split.validation and split.test
        assert split.train_end_epoch_ms <= split.validation_end_epoch_ms <= split.test_end_epoch_ms
        train_ts = {f.computed_at_epoch_ms for f in split.train}
        val_ts = {f.computed_at_epoch_ms for f in split.validation}
        test_ts = {f.computed_at_epoch_ms for f in split.test}
        assert max(train_ts) <= min(val_ts)
        assert max(val_ts) <= min(test_ts)

    def test_disjoint_periods(self) -> None:
        items = _dataset().features
        split = temporal_split(items)
        train_ids = {f.session_id for f in split.train}
        val_ids = {f.session_id for f in split.validation}
        test_ids = {f.session_id for f in split.test}
        assert not (train_ids & val_ids) and not (val_ids & test_ids) and not (train_ids & test_ids)

    def test_boundaries_reported(self) -> None:
        split = temporal_split(_dataset().features)
        assert set(split.boundaries) == {
            "train_end_epoch_ms", "validation_end_epoch_ms", "test_end_epoch_ms"
        }

    def test_if_trained_on_train_period_only(self) -> None:
        ds = _dataset()
        split = temporal_split(ds.features)
        model = fit_isolation_forest(split.train, seed=42, n_estimators=30)
        assert model is not None
        # training distribution consists of normal-ish sessions; outliers still
        # score high at inference — but the model never saw test data
        assert model.fitted_ is True

    def test_too_few_training_rows_returns_none(self) -> None:
        ds = _dataset()
        split = temporal_split(ds.features)
        assert fit_isolation_forest(split.train[-5:], seed=42) is None


class TestVariants:
    def _stacks(self) -> dict[str, ScoringStack]:
        return {
            "A": ScoringStack(variant="A", baseline_version="bl-test"),
            "B": ScoringStack(variant="B", baseline_version="bl-test"),
            "C": ScoringStack(variant="C", baseline_version="bl-test"),
            "D": ScoringStack(variant="D", baseline_version="bl-test"),
        }

    def test_all_variants_score_all_test_sessions(self) -> None:
        harness = EvaluationHarness(self._stacks())
        report = harness.run(_dataset())
        assert report["test_session_count"] > 0
        for name in ("A", "B", "C", "D"):
            assert name in report["variants"]
            assert len(report["scored_by_variant"][name]) == report["test_session_count"]

    def test_metrics_shape(self) -> None:
        harness = EvaluationHarness(self._stacks())
        report = harness.run(_dataset())
        for name, res in report["variants"].items():
            m = res["metrics"]
            for key in ("precision", "recall", "f1", "false_positive_rate", "pr_auc", "roc_auc"):
                assert key in m
            assert 0.0 <= m["pr_auc"] <= 1.0

    def test_f1_between_zero_and_one(self) -> None:
        harness = EvaluationHarness(self._stacks())
        report = harness.run(_dataset())
        for res in report["variants"].values():
            f1 = res["metrics"]["f1"]
            assert f1 is None or 0.0 <= f1 <= 1.0

    def test_model_version_on_every_scored_session(self) -> None:
        harness = EvaluationHarness(self._stacks())
        report = harness.run(_dataset())
        for scored in report["scored_by_variant"]["C"]:
            m = scored.model
            assert m.model_name and m.model_version and m.feature_version
            assert m.scoring_version and m.variant == "C"
            assert m.baseline_version == "bl-test"

    def test_variant_c_fits_anomaly_model(self) -> None:
        harness = EvaluationHarness(self._stacks())
        report = harness.run(_dataset())
        # variant C produced anomaly scores for test sessions
        c_scored = report["scored_by_variant"]["C"]
        with_anomaly = [s for s in c_scored if s.anomaly_score is not None]
        assert with_anomaly, "expected IF anomaly scores in variant C"


class TestArtifacts:
    def test_all_five_artifacts_written(self, tmp_path: Path) -> None:
        harness = EvaluationHarness(self._stacks())
        report = harness.run(_dataset())
        paths = harness.write_artifacts(report, tmp_path)
        written = set(paths)
        assert {"metrics.json", "precision_recall.json", "roc_data.json", "ablation_base.json"} <= written
        for name in written:
            content = json.loads(Path(paths[name]).read_text(encoding="utf-8"))
            assert isinstance(content, dict)

        cal_path = harness.write_calibration_artifact(_dataset(), self._stacks()["B"], tmp_path)
        assert Path(cal_path).exists()
        cal = json.loads(Path(cal_path).read_text(encoding="utf-8"))
        assert "brier_score" in cal and "expected_calibration_error" in cal and "bins" in cal

    def test_artifacts_marked_synthetic(self, tmp_path: Path) -> None:
        harness = EvaluationHarness(self._stacks())
        report = harness.run(_dataset())
        paths = harness.write_artifacts(report, tmp_path)
        metrics = json.loads(Path(paths["metrics.json"]).read_text(encoding="utf-8"))
        assert metrics["synthetic"] is True

    def _stacks(self) -> dict[str, ScoringStack]:
        return {
            "A": ScoringStack(variant="A"),
            "B": ScoringStack(variant="B"),
            "C": ScoringStack(variant="C"),
            "D": ScoringStack(variant="D"),
        }


class TestDeterminism:
    def test_replay_runs_are_identical(self) -> None:
        ds = _dataset()
        harness1 = EvaluationHarness(self._stacks())
        harness2 = EvaluationHarness(self._stacks())
        r1 = harness1.run(ds)
        r2 = harness2.run(ds)
        m1 = {k: v["metrics"] for k, v in r1["variants"].items()}
        m2 = {k: v["metrics"] for k, v in r2["variants"].items()}
        assert m1 == m2

    def _stacks(self) -> dict[str, ScoringStack]:
        return {
            "A": ScoringStack(variant="A"),
            "B": ScoringStack(variant="B"),
            "C": ScoringStack(variant="C"),
            "D": ScoringStack(variant="D"),
        }

    def test_same_stack_same_score(self) -> None:
        ds = _dataset()
        stack1 = ScoringStack(variant="C")
        stack2 = ScoringStack(variant="C")
        fsets = ds.features[:20]
        for f1, f2 in zip(fsets, fsets):
            assert stack1.score(f1).risk_score == stack2.score(f2).risk_score


class TestMetricFunctions:
    def test_classification_metrics_perfect(self) -> None:
        m = classification_metrics([0.1, 0.9], [0, 1], threshold=0.5)
        assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["false_positive_rate"] == 0.0

    def test_classification_metrics_all_wrong(self) -> None:
        m = classification_metrics([0.9, 0.1], [0, 1], threshold=0.5)
        assert m["fp"] == 1 and m["fn"] == 1

    def test_pr_auc_bounds(self) -> None:
        assert pr_auc([0.9, 0.1], [1, 0]) == 1.0
        # inverted ordering: the single positive is ranked last -> 0.5 here
        assert pr_auc([0.1, 0.9], [1, 0]) == pytest.approx(0.5)

    def test_roc_curve_has_diagonal_points(self) -> None:
        points = roc_curve([0.9, 0.1], [1, 0])
        assert points[0] == {"fpr": 0.0, "tpr": 0.0}
        assert points[-1] == {"fpr": 1.0, "tpr": 1.0}
