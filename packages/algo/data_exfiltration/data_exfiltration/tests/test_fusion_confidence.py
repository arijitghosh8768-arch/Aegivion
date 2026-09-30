"""Fusion, confidence, severity, and supervised-gate tests."""

from __future__ import annotations

import pytest

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    AvailableFeature,
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.confidence_engine import (
    ConfidenceEngine,
    ConfidenceState,
    FindingConfidenceCalibrator,
    brier_score,
    expected_calibration_error,
)
from algo.data_exfiltration.data_exfiltration.ml.feature_vector import FEATURE_NAMES
from algo.data_exfiltration.data_exfiltration.ml.fusion import FusionWeights, WeightedFusionEngine
from algo.data_exfiltration.data_exfiltration.ml.rules import RulePolicy
from algo.data_exfiltration.data_exfiltration.ml.severity import Severity, SeverityInputs, severity_from
from algo.data_exfiltration.data_exfiltration.ml.supervised import (
    LabeledDataset,
    LabelGateError,
    SupervisedModelGate,
    train_supervised,
)
from algo.data_exfiltration.data_exfiltration.ml.feature_vector import build_feature_vector


def _fset(risk_like: float = 0.0, available_all: bool = True) -> BehavioralFeatureSet:
    fset = BehavioralFeatureSet(
        subject_id="a", session_id="s", actor_id="a", computed_at_epoch_ms=1.0,
    )
    avail = FeatureAvailability.OBSERVED if available_all else FeatureAvailability.UNAVAILABLE
    def _f(v: float | None) -> AvailableFeature:
        if v is None:
            return AvailableFeature(availability=FeatureAvailability.UNAVAILABLE)
        return AvailableFeature(value=v, availability=avail)
    fset.volume_score = _f(risk_like)
    fset.object_count_score = _f(risk_like * 0.8)
    fset.request_rate_score = _f(risk_like * 0.8)
    fset.destination_score = _f(risk_like)
    fset.access_pattern_score = _f(risk_like * 0.6)
    fset.sensitivity_score = _f(0.3)
    fset.time_score = _f(risk_like * 0.5)
    fset.actor_resource_score = _f(risk_like * 0.7)
    fset.egress_score = _f(risk_like * 0.9)
    fset.baseline_quality = 0.9
    return fset.finalize()


class TestFusion:
    def test_full_availability_weights_sum_to_risk(self) -> None:
        engine = WeightedFusionEngine()
        fset = _fset(0.5)
        result = engine.fuse(fset, anomaly_score=0.4)
        assert 0.0 <= result.risk_score <= 1.0
        assert result.renormalized is False
        assert result.missing_components == []
        assert abs(sum(result.contributions.values()) - result.risk_score) < 1e-6

    def test_unavailable_component_renormalized_not_zero(self) -> None:
        engine = WeightedFusionEngine()
        fset = _fset(0.5)
        fset.egress_score = AvailableFeature(availability=FeatureAvailability.UNAVAILABLE)
        fset = fset.finalize()
        result = engine.fuse(fset, anomaly_score=None)
        assert "egress" in result.missing_components
        assert "anomaly" in result.missing_components
        assert result.renormalized is True
        # risk is NOT diluted by missing components
        assert result.risk_score > 0

    def test_weights_versioned_by_content(self) -> None:
        w1 = FusionWeights(volume=0.2)
        w2 = FusionWeights(volume=0.2)
        w3 = FusionWeights(volume=0.3)
        assert w1.version_id() == w2.version_id()
        assert w1.version_id() != w3.version_id()

    def test_risk_is_not_confidence_separate_outputs(self) -> None:
        engine = WeightedFusionEngine()
        result = engine.fuse(_fset(0.7), anomaly_score=0.6)
        confidence = ConfidenceEngine().assess(
            _fset(0.7), risk_score=result.risk_score, rules_score=0.5, anomaly_score=0.6
        )
        # independent assessments; neither derives from the other's number
        assert 0.0 <= result.risk_score <= 1.0
        assert confidence.confidence_score is None or 0.0 <= confidence.confidence_score <= 1.0


class TestRulePolicy:
    def test_quiet_session_low_rules_score(self) -> None:
        assessment = RulePolicy().evaluate(_fset(0.05))
        assert assessment.rules_score < 0.3
        assert assessment.fired == []

    def test_high_risk_signals_fire_rules(self) -> None:
        fset = _fset(0.9)
        fset.destination_score = AvailableFeature(
            value=1.0,
            availability=FeatureAvailability.OBSERVED,
            detail={"worst_class": "high_risk_external"},
        )
        assessment = RulePolicy().evaluate(fset.finalize())
        assert "high_risk_destination" in assessment.fired
        assert assessment.rules_score > 0.4

    def test_thin_evidence_keeps_score_low(self) -> None:
        fset = _fset(0.9)
        fset.sensitivity_score = AvailableFeature(value=0.7, availability=FeatureAvailability.OBSERVED)
        # only sensitivity measurable; every other dimension unavailable
        for name in ("volume_score", "object_count_score", "request_rate_score",
                     "destination_score", "access_pattern_score", "time_score",
                     "actor_resource_score", "egress_score"):
            setattr(fset, name, AvailableFeature(availability=FeatureAvailability.UNAVAILABLE))
        assessment = RulePolicy().evaluate(fset.finalize())
        # only the sensitivity rule contributes, and modestly
        assert set(assessment.contributions) == {"sensitivity"}
        assert "sensitive_data_access" in assessment.fired
        assert assessment.rules_score < 0.5


class TestConfidenceEngine:
    def test_thin_evidence_insufficient_data_state(self) -> None:
        engine = ConfidenceEngine(min_features_for_heuristic=4)
        fset = _fset(0.5, available_all=False)
        assessment = engine.assess(fset, risk_score=0.5)
        assert assessment.state is ConfidenceState.INSUFFICIENT_DATA
        assert assessment.confidence_score is None  # no fake probability

    def test_rich_evidence_heuristic_state(self) -> None:
        engine = ConfidenceEngine()
        fset = _fset(0.5)
        fset.baseline_quality = 0.9
        assessment = engine.assess(fset, risk_score=0.5, rules_score=0.5, anomaly_score=0.5)
        assert assessment.state is ConfidenceState.HEURISTIC
        assert assessment.confidence_score is not None
        assert assessment.detail["note"]  # explicitly not a probability

    def test_calibrated_path_requires_both_classes(self) -> None:
        calibrator = FindingConfidenceCalibrator()
        scores = [0.1, 0.2, 0.3, 0.8, 0.9] * 5
        labels = [0, 0, 0, 1, 1] * 5
        assert calibrator.fit(scores, labels) is True
        assert calibrator.metrics["brier_score"] >= 0.0
        engine = ConfidenceEngine(calibrator)
        assessment = engine.assess(_fset(0.8), risk_score=0.85)
        assert assessment.state is ConfidenceState.CALIBRATED

    def test_calibration_refuses_insufficient_labels(self) -> None:
        calibrator = FindingConfidenceCalibrator()
        assert calibrator.fit([0.2, 0.8], [0, 1]) is False
        engine = ConfidenceEngine(calibrator)
        assessment = engine.assess(_fset(0.5), risk_score=0.5)
        assert assessment.state is ConfidenceState.HEURISTIC  # fell back honestly

    def test_brier_and_ece_math(self) -> None:
        # perfect predictions
        assert brier_score([0.0, 1.0], [0, 1]) == 0.0
        # worst predictions
        assert brier_score([1.0, 0.0], [0, 1]) == 1.0
        # per-bin accuracy equal to mean predicted confidence -> ECE 0
        probs = [0.25] * 8 + [0.75] * 8
        labels = [0, 0, 1, 0, 0, 1, 0, 0] + [1, 1, 1, 1, 1, 1, 0, 0]
        assert expected_calibration_error(probs, labels) == pytest.approx(0.0, abs=1e-6)


class TestSeverity:
    def test_bands(self) -> None:
        assert severity_from(SeverityInputs(risk_score=0.1)) is Severity.LOW
        assert severity_from(SeverityInputs(risk_score=0.5)) is Severity.MEDIUM
        assert severity_from(SeverityInputs(risk_score=0.7)) is Severity.HIGH
        assert severity_from(SeverityInputs(risk_score=0.95)) is Severity.CRITICAL

    def test_thin_evidence_caps_critical(self) -> None:
        severity = severity_from(SeverityInputs(risk_score=0.95, evidence_quality=0.2))
        assert severity is Severity.MEDIUM

    def test_low_confidence_caps_critical(self) -> None:
        severity = severity_from(SeverityInputs(risk_score=0.95, confidence=0.2, evidence_quality=0.9))
        assert severity is Severity.HIGH

    def test_sensitive_data_promotes(self) -> None:
        severity = severity_from(
            SeverityInputs(risk_score=0.65, confidence=0.9, evidence_quality=0.9, sensitivity=0.8)
        )
        assert severity is Severity.CRITICAL


class TestSupervisedGate:
    def _dataset(self, n_pos: int = 12, n_neg: int = 12) -> LabeledDataset:
        from algo.data_exfiltration.data_exfiltration.ml.feature_vector import MLFeatureVector

        vectors, labels = [], []
        for i in range(n_neg):
            values = {name: 0.05 for name in FEATURE_NAMES}
            vectors.append(MLFeatureVector(
                subject_id="n", session_id=f"n{i}", computed_at_epoch_ms=float(i),
                values=values, availability={name: "observed" for name in FEATURE_NAMES},
            ))
            labels.append(0)
        for i in range(n_pos):
            values = {name: 0.9 for name in FEATURE_NAMES}
            vectors.append(MLFeatureVector(
                subject_id="p", session_id=f"p{i}", computed_at_epoch_ms=float(i),
                values=values, availability={name: "observed" for name in FEATURE_NAMES},
            ))
            labels.append(1)
        return LabeledDataset(vectors=vectors, labels=labels, synthetic=True, source="unit_test")

    def test_gate_allows_labeled_data(self) -> None:
        gate = SupervisedModelGate()
        ok, reason = gate.check(self._dataset())
        assert ok is True

    def test_gate_refuses_unlabeled_or_imbalanced(self) -> None:
        ds = self._dataset(n_pos=3, n_neg=12)
        ok, reason = SupervisedModelGate().check(ds)
        assert ok is False
        assert "insufficient" in reason

    def test_train_refuses_insufficient_labels(self) -> None:
        with pytest.raises(LabelGateError):
            train_supervised(self._dataset(n_pos=2, n_neg=12))

    def test_trained_model_separates_classes(self) -> None:
        ds = self._dataset()
        model = train_supervised(ds)
        from algo.data_exfiltration.data_exfiltration.ml.feature_vector import MLFeatureVector

        neg = MLFeatureVector(
            subject_id="n", session_id="x", computed_at_epoch_ms=0.0,
            values={name: 0.05 for name in FEATURE_NAMES},
            availability={name: "observed" for name in FEATURE_NAMES},
        )
        pos = MLFeatureVector(
            subject_id="p", session_id="y", computed_at_epoch_ms=0.0,
            values={name: 0.9 for name in FEATURE_NAMES},
            availability={name: "observed" for name in FEATURE_NAMES},
        )
        assert model.score(pos) > model.score(neg)
        assert model.synthetic_training_data is True  # never hidden

    def test_labels_never_fabricated_for_real_data(self) -> None:
        ds = self._dataset(n_pos=0, n_neg=0)
        ok, reason = SupervisedModelGate().check(ds)
        assert ok is False
