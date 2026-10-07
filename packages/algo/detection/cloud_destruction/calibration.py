"""Calibration metrics — **Part 3**.

Brier score and Expected Calibration Error (ECE) for evaluating
supervised probabilities. Used by the confidence engine and the
evaluation framework; never used to *pretend* a model is calibrated —
the numbers are reported alongside the model that produced them.

Synthetic-label discipline applies: metrics computed on synthetic labels
are reported with ``label_source="synthetic"``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

__all__ = ["CalibrationReport", "brier_score", "expected_calibration_error", "evaluate_calibration"]


@dataclass
class CalibrationReport:
    """Calibration evaluation of probabilistic predictions."""

    brier_score: float
    expected_calibration_error: float
    n_samples: int
    label_source: Optional[str] = None
    """``"synthetic"`` when computed on synthetic labels."""

    def to_log_dict(self) -> dict[str, object]:
        return {
            "brier_score": self.brier_score,
            "expected_calibration_error": self.expected_calibration_error,
            "n_samples": self.n_samples,
            "label_source": self.label_source,
        }


def brier_score(probabilities: Sequence[float], labels: Sequence[int]) -> float:
    """Mean squared error of probabilities against outcomes (0 = perfect)."""
    if len(probabilities) != len(labels) or not probabilities:
        raise ValueError("probabilities and labels must be non-empty and equal length")
    return sum((p - float(y)) ** 2 for p, y in zip(probabilities, labels)) / len(probabilities)


def expected_calibration_error(
    probabilities: Sequence[float],
    labels: Sequence[int],
    n_bins: int = 10,
) -> float:
    """ECE over ``n_bins`` equal-width bins in ``[0, 1]``."""
    if len(probabilities) != len(labels) or not probabilities:
        raise ValueError("probabilities and labels must be non-empty and equal length")
    bin_totals = [0] * n_bins
    bin_correct = [0.0] * n_bins
    bin_confident = [0.0] * n_bins
    for p, y in zip(probabilities, labels):
        index = min(n_bins - 1, max(0, int(p * n_bins)))
        bin_totals[index] += 1
        bin_confident[index] += p
        bin_correct[index] += float(y)
    n = len(probabilities)
    ece = 0.0
    for total, correct, confident in zip(bin_totals, bin_correct, bin_confident):
        if total == 0:
            continue
        accuracy = correct / total
        confidence = confident / total
        ece += (total / n) * abs(confidence - accuracy)
    return ece


def evaluate_calibration(
    probabilities: Sequence[float],
    labels: Sequence[int],
    *,
    label_source: Optional[str] = None,
) -> CalibrationReport:
    """Compute the full calibration report for one set of predictions."""
    return CalibrationReport(
        brier_score=brier_score(probabilities, labels),
        expected_calibration_error=expected_calibration_error(probabilities, labels),
        n_samples=len(probabilities),
        label_source=label_source,
    )
