"""Confidence engine — confidence is NOT risk.

Confidence depends on:
- feature availability      (share of features actually measurable)
- baseline quality          (how much trusted history backs the features)
- source reliability        (observed vs estimated inputs)
- model agreement           (rules vs ML direction)
- evidence consistency      (do independent signals point the same way?)

Calibration: when enough LABELED data exists, probabilities are
calibrated with Platt scaling (logistic on raw risk, temperature-style);
Brier score and Expected Calibration Error are provided to measure it.
When there is not enough labeled data, we do NOT pretend confidence is a
probability: the assessment carries an explicit ``ConfidenceState``
(``insufficient_data``) and no calibrated value.
"""

from __future__ import annotations

import math
from enum import Enum
from typing import Any, Sequence

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    BehavioralFeatureSet,
    FeatureAvailability,
)


class ConfidenceState(str, Enum):
    CALIBRATED = "calibrated"            # backed by labeled-data calibration
    HEURISTIC = "heuristic"              # honest heuristic, not a probability
    INSUFFICIENT_DATA = "insufficient_data"  # no confidence claim made


class ConfidenceAssessment(BaseModel):
    session_id: str
    confidence_score: float | None = None
    """0..1. A probability ONLY when state == calibrated."""
    state: ConfidenceState = ConfidenceState.INSUFFICIENT_DATA
    components: dict[str, float | None] = Field(default_factory=dict)
    detail: dict[str, Any] = Field(default_factory=dict)


class PlattCalibrator:
    """Platt scaling: logistic regression of labels on raw scores (1-D).

    Fit requires both classes present; otherwise returns None (caller
    must not pretend calibration happened).
    """

    def __init__(self) -> None:
        self.a: float | None = None
        self.b: float | None = None

    def fit(self, scores: Sequence[float], labels: Sequence[int], *, lr: float = 0.5, epochs: int = 2000) -> bool:
        if len(scores) != len(labels) or not scores:
            return False
        if len(set(labels)) < 2:
            return False  # single-class data cannot calibrate
        a, b = 0.0, 0.0
        n = len(scores)
        for _ in range(epochs):
            grad_a = grad_b = 0.0
            for s, y in zip(scores, labels):
                p = 1.0 / (1.0 + math.exp(-(a * s + b)))
                err = p - y
                grad_a += err * s
                grad_b += err
            a -= lr * grad_a / n
            b -= lr * grad_b / n
        self.a, self.b = a, b
        return True

    def transform(self, score: float) -> float | None:
        if self.a is None or self.b is None:
            return None
        return 1.0 / (1.0 + math.exp(-(self.a * score + self.b)))


def brier_score(probabilities: Sequence[float], labels: Sequence[int]) -> float:
    """Mean squared error of probabilities vs binary labels."""
    if not probabilities or len(probabilities) != len(labels):
        raise ValueError("brier_score requires aligned non-empty inputs")
    return round(sum((p - y) ** 2 for p, y in zip(probabilities, labels)) / len(probabilities), 6)


def expected_calibration_error(
    probabilities: Sequence[float],
    labels: Sequence[int],
    bins: int = 10,
) -> float:
    """ECE: |confidence - accuracy| weighted by bin occupancy."""
    if not probabilities or len(probabilities) != len(labels):
        raise ValueError("expected_calibration_error requires aligned inputs")
    n = len(probabilities)
    ece = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i in range(n) if lo <= probabilities[i] < hi or (b == bins - 1 and probabilities[i] == hi)]
        if not idx:
            continue
        acc = sum(labels[i] for i in idx) / len(idx)
        conf = sum(probabilities[i] for i in idx) / len(idx)
        ece += (len(idx) / n) * abs(conf - acc)
    return round(ece, 6)


class FindingConfidenceCalibrator:
    """Fit-on-labeled-data calibrator; refuses when data is insufficient."""

    MIN_SAMPLES_PER_CLASS = 10

    def __init__(self) -> None:
        self._platt: PlattCalibrator | None = None
        self._brier: float | None = None
        self._ece: float | None = None

    @property
    def metrics(self) -> dict[str, float]:
        out: dict[str, float] = {}
        if self._brier is not None:
            out["brier_score"] = self._brier
        if self._ece is not None:
            out["expected_calibration_error"] = self._ece
        return out

    def fit(self, scores: Sequence[float], labels: Sequence[int]) -> bool:
        """Calibrate only with enough labeled data of BOTH classes."""
        positives = sum(1 for y in labels if y == 1)
        negatives = sum(1 for y in labels if y == 0)
        if positives < self.MIN_SAMPLES_PER_CLASS or negatives < self.MIN_SAMPLES_PER_CLASS:
            return False
        platt = PlattCalibrator()
        if not platt.fit(scores, labels):
            return False
        self._platt = platt
        calibrated = [platt.transform(s) for s in scores]
        self._brier = brier_score(calibrated, labels)
        self._ece = expected_calibration_error(calibrated, labels)
        return True

    def calibrate(self, score: float) -> float | None:
        if self._platt is None:
            return None
        return self._platt.transform(score)


class ConfidenceEngine:
    """Produces confidence assessments (never risk)."""

    def __init__(
        self,
        calibrator: FindingConfidenceCalibrator | None = None,
        *,
        min_features_for_heuristic: int = 4,
    ) -> None:
        self._calibrator = calibrator
        self._min_features = min_features_for_heuristic

    def assess(
        self,
        fset: BehavioralFeatureSet,
        *,
        risk_score: float,
        rules_score: float | None = None,
        anomaly_score: float | None = None,
    ) -> ConfidenceAssessment:
        from algo.data_exfiltration.data_exfiltration.ml.feature_vector import FEATURE_NAMES

        # 1) feature availability share
        availability = fset.feature_availability or {
            name: getattr(fset, name).availability.value for name in FEATURE_NAMES
        }
        available_count = sum(1 for v in availability.values() if v != FeatureAvailability.UNAVAILABLE.value)
        feature_availability = available_count / len(FEATURE_NAMES)

        # 2) baseline quality + source reliability from provenance
        baseline_quality = float(fset.baseline_quality)
        provenance_values = list((fset.feature_provenance or {}).values())
        observed_marks = sum(1 for p in provenance_values if p in ("personal", "observed"))
        source_reliability = (
            observed_marks / len(provenance_values) if provenance_values else 0.0
        )

        # 3) model agreement (rules vs ML), only when both exist
        model_agreement: float | None = None
        if rules_score is not None and anomaly_score is not None:
            model_agreement = 1.0 - min(1.0, abs(rules_score - anomaly_score))

        # 4) evidence consistency: pairwise agreement among available signals
        signals = [
            f.value
            for f in (
                fset.volume_score, fset.destination_score, fset.access_pattern_score,
                fset.time_score, fset.actor_resource_score, fset.egress_score,
            )
            if f.value is not None
        ]
        if len(signals) >= 2:
            def _agreement(a: float, b: float) -> float:
                hi, lo = max(a, b), min(a, b)
                if hi <= 0:
                    return 1.0
                return 1.0 - (hi - lo) / hi
            pairs = [
                _agreement(signals[i], signals[j])
                for i in range(len(signals))
                for j in range(i + 1, len(signals))
            ]
            evidence_consistency = round(sum(pairs) / len(pairs), 6)
        else:
            evidence_consistency = None

        components = {
            "feature_availability": round(feature_availability, 6),
            "baseline_quality": round(baseline_quality, 6),
            "source_reliability": round(source_reliability, 6),
            "model_agreement": (
                round(model_agreement, 6) if model_agreement is not None else None
            ),
            "evidence_consistency": (
                round(evidence_consistency, 6) if evidence_consistency is not None else None
            ),
        }

        # calibrated path (labeled data only)
        if self._calibrator is not None and self._calibrator._platt is not None:
            calibrated = self._calibrator.calibrate(risk_score)
            if calibrated is not None:
                return ConfidenceAssessment(
                    session_id=fset.session_id,
                    confidence_score=round(calibrated, 6),
                    state=ConfidenceState.CALIBRATED,
                    components=components,
                    detail={"calibration_metrics": self._calibrator.metrics},
                )

        # heuristic path (explicitly NOT a probability)
        if available_count < self._min_features:
            return ConfidenceAssessment(
                session_id=fset.session_id,
                confidence_score=None,
                state=ConfidenceState.INSUFFICIENT_DATA,
                components=components,
                detail={"reason": "too few measurable features for any confidence claim"},
            )

        weighted = (
            0.30 * feature_availability
            + 0.25 * baseline_quality
            + 0.20 * source_reliability
            + (0.15 * model_agreement if model_agreement is not None else 0.0)
            + (0.10 * evidence_consistency if evidence_consistency is not None else 0.0)
        )
        return ConfidenceAssessment(
            session_id=fset.session_id,
            confidence_score=round(min(1.0, weighted), 6),
            state=ConfidenceState.HEURISTIC,
            components=components,
            detail={
                "note": "heuristic confidence; not a calibrated probability",
            },
        )
