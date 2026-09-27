"""Evaluation metrics - **Part 4 (research)**.

Implemented from first principles (no sklearn dependency): precision, recall,
F1, PR-AUC (step-wise interpolation), ROC-AUC (rank statistic), FPR, FNR,
detection latency (events), detection lead time (minutes), Brier score,
expected calibration error, precision-at-fixed-recall and
recall-at-fixed-FPR. Deterministic and dependency-free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

import math


@dataclass
class ConfusionMatrix:
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    @property
    def precision(self) -> Optional[float]:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 6) if denom else None

    @property
    def recall(self) -> Optional[float]:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 6) if denom else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return round(2 * p * r / (p + r), 6)

    @property
    def fpr(self) -> Optional[float]:
        denom = self.false_positives + self.true_negatives
        return round(self.false_positives / denom, 6) if denom else None

    @property
    def fnr(self) -> Optional[float]:
        denom = self.true_positives + self.false_negatives
        return round(self.false_negatives / denom, 6) if denom else None

    def as_dict(self) -> dict[str, Optional[float]]:
        return {
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "tn": self.true_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "fpr": self.fpr,
            "fnr": self.fnr,
        }


@dataclass
class LatencyStats:
    """Detection latency measured in *events observed* before first TP."""

    detection_latency_events: Optional[int] = None
    detection_lead_time_minutes: Optional[float] = None
    first_tp_event_index: Optional[int] = None

    def as_dict(self) -> dict[str, Optional[float]]:
        return {
            "detection_latency_events": self.detection_latency_events,
            "detection_lead_time_minutes": self.detection_lead_time_minutes,
            "first_tp_event_index": self.first_tp_event_index,
        }


def pr_auc(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    """Average-precision style PR-AUC (step interpolation)."""
    if len(y_true) != len(scores) or not y_true:
        return None
    pairs = sorted(zip(scores, y_true), key=lambda p: -p[0])
    total_pos = sum(y_true)
    if total_pos == 0:
        return None
    seen_pos = 0
    seen = 0
    auc = 0.0
    prev_recall = 0.0
    for score, label in pairs:
        seen += 1
        if label == 1:
            seen_pos += 1
            recall = seen_pos / total_pos
            precision = seen_pos / seen
            auc += (recall - prev_recall) * precision
            prev_recall = recall
    return round(auc, 6)


def roc_auc(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    """Rank-statistic ROC-AUC with tie handling (Mann-Whitney U)."""
    if len(y_true) != len(scores) or not y_true:
        return None
    n_pos = sum(1 for y in y_true if y == 1)
    n_neg = len(y_true) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg_rank = (i + j) / 2 + 1  # 1-based average rank for the tie group
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1
    sum_pos_ranks = sum(r for r, y in zip(ranks, y_true) if y == 1)
    u = sum_pos_ranks - n_pos * (n_pos + 1) / 2
    return round(u / (n_pos * n_neg), 6)


def brier_score(probabilities: Sequence[float], labels: Sequence[int]) -> Optional[float]:
    if not probabilities or len(probabilities) != len(labels):
        return None
    return round(
        sum((p - float(y)) ** 2 for p, y in zip(probabilities, labels)) / len(probabilities), 6
    )


def expected_calibration_error(
    probabilities: Sequence[float],
    labels: Sequence[int],
    bins: int = 10,
) -> Optional[float]:
    if not probabilities or len(probabilities) != len(labels):
        return None
    buckets: dict[int, list[float]] = {}
    for p, y in zip(probabilities, labels):
        idx = min(bins - 1, int(p * bins))
        buckets.setdefault(idx, []).append(float(y) - p)
    total = len(probabilities)
    ece = 0.0
    for errors in buckets.values():
        ece += (len(errors) / total) * abs(sum(errors) / len(errors))
    return round(ece, 6)


def precision_at_recall(
    y_true: Sequence[int], scores: Sequence[float], target_recall: float
) -> Optional[float]:
    """Best precision achievable at recall >= target (sweep all thresholds)."""
    if not y_true or len(y_true) != len(scores):
        return None
    total_pos = sum(y_true)
    if total_pos == 0:
        return None
    pairs = sorted(zip(scores, y_true), key=lambda p: -p[0])
    best: Optional[float] = None
    seen_pos = 0
    for idx, (score, label) in enumerate(pairs):
        if label == 1:
            seen_pos += 1
        recall = seen_pos / total_pos
        if recall >= target_recall:
            precision = seen_pos / (idx + 1)
            if best is None or precision > best:
                best = precision
    return round(best, 6) if best is not None else None


def recall_at_fpr(
    y_true: Sequence[int], scores: Sequence[float], target_fpr: float
) -> Optional[float]:
    """Best recall achievable at FPR <= target (sweep operating points).

    Operating points are evaluated per distinct score value: all rows sharing
    a score are accepted together (they cannot be split by a threshold).
    """
    if not y_true or len(y_true) != len(scores):
        return None
    total_pos = sum(1 for y in y_true if y == 1)
    total_neg = len(y_true) - total_pos
    if total_neg == 0 or total_pos == 0:
        return None
    pairs = sorted(zip(scores, y_true), key=lambda p: -p[0])
    best: Optional[float] = None
    seen_pos = 0
    seen_neg = 0
    idx = 0
    while idx < len(pairs):
        score = pairs[idx][0]
        group_pos = group_neg = 0
        while idx < len(pairs) and pairs[idx][0] == score:
            if pairs[idx][1] == 1:
                group_pos += 1
            else:
                group_neg += 1
            idx += 1
        # Operating point after accepting this whole score group.
        seen_pos += group_pos
        seen_neg += group_neg
        fpr = seen_neg / total_neg
        if fpr <= target_fpr:
            recall = seen_pos / total_pos
            if best is None or recall > best:
                best = recall
        else:
            break
    return round(best, 6) if best is not None else None


def pr_curve_points(
    y_true: Sequence[int], scores: Sequence[float]
) -> list[dict[str, float]]:
    """Precision/recall pairs across all thresholds (for PR plots)."""
    if not y_true or len(y_true) != len(scores):
        return []
    total_pos = sum(y_true)
    if total_pos == 0:
        return []
    pairs = sorted(zip(scores, y_true), key=lambda p: -p[0])
    points: list[dict[str, float]] = []
    seen_pos = 0
    for idx, (score, label) in enumerate(pairs):
        if label == 1:
            seen_pos += 1
        points.append(
            {
                "threshold": round(float(score), 6),
                "precision": round(seen_pos / (idx + 1), 6),
                "recall": round(seen_pos / total_pos, 6),
            }
        )
    return points


def calibration_curve_points(
    probabilities: Sequence[float], labels: Sequence[int], bins: int = 10
) -> list[dict[str, float]]:
    """Reliability diagram data: mean predicted vs observed per bin."""
    if not probabilities or len(probabilities) != len(labels):
        return []
    buckets: dict[int, list[tuple[float, int]]] = {}
    for p, y in zip(probabilities, labels):
        idx = min(bins - 1, int(p * bins))
        buckets.setdefault(idx, []).append((p, y))
    points: list[dict[str, float]] = []
    for idx in sorted(buckets):
        members = buckets[idx]
        points.append(
            {
                "bin": idx,
                "mean_predicted": round(sum(p for p, _ in members) / len(members), 6),
                "observed_rate": round(sum(y for _, y in members) / len(members), 6),
                "count": len(members),
            }
        )
    return points


def latency_stats(
    y_true: Sequence[int],
    predicted: Sequence[bool],
    timestamps: Sequence[object],
) -> LatencyStats:
    """Events-to-first-TP and lead time (first TP vs first true attack event)."""
    if not (len(y_true) == len(predicted) == len(timestamps)):
        raise ValueError("latency_stats needs equal-length inputs")
    first_tp: Optional[int] = None
    first_attack: Optional[int] = None
    for idx, (label, pred) in enumerate(zip(y_true, predicted)):
        if label == 1 and first_attack is None:
            first_attack = idx
        if label == 1 and pred and first_tp is None:
            first_tp = idx
    if first_tp is None:
        return LatencyStats()
    lead: Optional[float] = None
    if first_attack is not None:
        try:
            delta = timestamps[first_tp] - timestamps[first_attack]  # type: ignore[operator]
            lead = round(delta.total_seconds() / 60.0, 3)  # type: ignore[union-attr]
        except (AttributeError, TypeError):
            lead = None
    return LatencyStats(
        detection_latency_events=first_tp - (first_attack or 0),
        detection_lead_time_minutes=lead,
        first_tp_event_index=first_tp,
    )


__all__ = [
    "ConfusionMatrix",
    "LatencyStats",
    "brier_score",
    "calibration_curve_points",
    "expected_calibration_error",
    "latency_stats",
    "pr_auc",
    "pr_curve_points",
    "precision_at_recall",
    "recall_at_fpr",
    "roc_auc",
]
