"""Confidence calibration - **Part 2**.

Confidence answers a different question from risk:

* **risk** - how dangerous does this activity look?
* **confidence** - how strongly does the collected evidence support that?

They are separate outputs and must never be conflated: ``risk 91 with
confidence 0.74`` is a legitimate, common combination (high-stakes behavior,
incomplete corroboration).

Confidence here is *evidence-based*: it is derived from baseline quality,
signal corroboration and enrichment completeness, optionally recalibrated by
a supervised model's probabilities (Platt scaling / isotonic regression) when
labeled evaluation data exists. ``risk / 100`` is explicitly rejected as a
confidence source.
"""

from __future__ import annotations

import math
from typing import Callable, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from detection.credential_compromise.config import ConfidenceConfig
from detection.credential_compromise.schemas import BaselineQuality

_EVIDENCE_BASELINE = {
    BaselineQuality.EXCELLENT: 1.0,
    BaselineQuality.GOOD: 0.85,
    BaselineQuality.LIMITED: 0.55,
    BaselineQuality.COLD_START: 0.25,
}


class EvidenceContext(BaseModel):
    """What the conclusion rests on. Feeds confidence, not risk."""

    model_config = ConfigDict(frozen=True)

    baseline_quality: BaselineQuality = BaselineQuality.COLD_START
    is_peer_baseline: bool = False
    corroborating_signals: int = 0
    independent_dimensions_touched: int = 0
    enrichment_completeness: float = Field(default=0.0, ge=0.0, le=1.0)

    @property
    def baseline_component(self) -> float:
        component = _EVIDENCE_BASELINE.get(self.baseline_quality, 0.25)
        # A peer baseline is second-hand evidence: it can never fully stand in
        # for the identity's own history.
        return component * 0.8 if self.is_peer_baseline else component


def evidence_confidence(
    evidence: EvidenceContext,
    *,
    config: Optional[ConfidenceConfig] = None,
) -> float:
    """Weighted evidence score in [0, 1]. Deterministic and explainable."""
    config = config or ConfidenceConfig()
    corroboration = 0.0
    if evidence.corroborating_signals > 0:
        corroboration = min(1.0, 0.45 + 0.15 * (evidence.corroborating_signals - 1))
    dimensions = min(1.0, evidence.independent_dimensions_touched / 3.0)
    corroboration = max(corroboration, 0.6 * dimensions)
    return round(
        config.w_baseline * evidence.baseline_component
        + config.w_corroboration * corroboration
        + config.w_enrichment * max(0.0, min(1.0, evidence.enrichment_completeness)),
        4,
    )


# --------------------------------------------------------------------------- #
# Supervised calibration (Platt scaling / isotonic regression)
# --------------------------------------------------------------------------- #


def platt_scale(
    probabilities: Sequence[float],
    labels: Sequence[int],
    *,
    lr: float = 0.1,
    epochs: int = 500,
) -> tuple[float, float]:
    """Fit Platt scaling (logistic calibration on model outputs).

    Returns ``(a, b)`` for ``sigmoid(a * p + b)``. Fit on a *held-out*
    calibration set, never on training scores. Synthetic labels must be
    declared by the caller's reporting, not hidden here.
    """
    if len(probabilities) != len(labels) or not probabilities:
        raise ValueError("platt_scale needs equal-length, non-empty inputs")
    a, b = 1.0, 0.0
    for _ in range(epochs):
        grad_a = grad_b = 0.0
        for p, y in zip(probabilities, labels):
            activation = _sigmoid(a * p + b)
            error = activation - float(y)
            grad_a += error * p
            grad_b += error
        n = len(probabilities)
        a -= lr * grad_a / n
        b -= lr * grad_b / n
    return round(a, 6), round(b, 6)


def isotonic_calibrator(
    probabilities: Sequence[float],
    labels: Sequence[int],
) -> Callable[[float], float]:
    """Pool-adjacent-violators isotonic calibration on a held-out set."""
    if len(probabilities) != len(labels) or not probabilities:
        raise ValueError("isotonic_calibrator needs equal-length, non-empty inputs")
    pairs = sorted(zip(probabilities, labels))
    # PAV: merge adjacent violating blocks.
    blocks: list[list[float]] = []  # [sum_y, count, x_upper]
    for p, y in pairs:
        blocks.append([float(y), 1.0, p])
        while len(blocks) >= 2 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            upper = blocks.pop()
            lower = blocks.pop()
            blocks.append([lower[0] + upper[0], lower[1] + upper[1], upper[2]])

    def calibrate(p: float) -> float:
        for _sum_y, count, x_upper in blocks:
            if p <= x_upper:
                return round(_sum_y / count, 6)
        return round(blocks[-1][0] / blocks[-1][1], 6) if blocks else 0.0

    return calibrate


def _sigmoid(z: float) -> float:
    if z < 0:
        exp_z = math.exp(z)
        return exp_z / (1.0 + exp_z)
    return 1.0 / (1.0 + math.exp(-z))


# --------------------------------------------------------------------------- #
# Calibration quality metrics
# --------------------------------------------------------------------------- #


def brier_score(probabilities: Sequence[float], labels: Sequence[int]) -> float:
    """Brier score; 0 is perfect, 0.25 is uninformed."""
    if not probabilities or len(probabilities) != len(labels):
        raise ValueError("brier_score needs equal-length, non-empty inputs")
    return round(
        sum((p - float(y)) ** 2 for p, y in zip(probabilities, labels)) / len(probabilities),
        6,
    )


def expected_calibration_error(
    probabilities: Sequence[float],
    labels: Sequence[int],
    *,
    bins: int = 10,
) -> float:
    """ECE over equal-width probability bins; 0 is perfectly calibrated."""
    if not probabilities or len(probabilities) != len(labels):
        raise ValueError("expected_calibration_error needs equal-length, non-empty inputs")
    bucket_acc: dict[int, list[float]] = {}
    for p, y in zip(probabilities, labels):
        idx = min(bins - 1, int(p * bins))
        bucket_acc.setdefault(idx, []).append(float(y) - p)
    total = len(probabilities)
    ece = 0.0
    for idx, errors in bucket_acc.items():
        gap = abs(sum(errors) / len(errors))
        ece += (len(errors) / total) * gap
    return round(ece, 6)


__all__ = [
    "EvidenceContext",
    "brier_score",
    "evidence_confidence",
    "expected_calibration_error",
    "isotonic_calibrator",
    "platt_scale",
]
