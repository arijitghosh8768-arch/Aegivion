"""Threshold tuning with strict train/validation/test separation.

The rule this module enforces: **the test period is scored once and never
consulted while choosing a threshold.** The operating threshold is selected
on the validation period, then frozen and applied to the (chronologically
later) test period. Any leak of test data into the selection is a bug here,
not a tuning nuance.

It also exposes explicit split utilities and an integrity check so the
separation can be asserted in tests rather than assumed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.ml.evaluation import _r, classification_metrics
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack, ScoredSession
from algo.data_exfiltration.data_exfiltration.ml.replay import (
    TemporalSplit,
    fit_isolation_forest,
    temporal_split,
)

from .metrics import full_metrics

#: Candidate operating thresholds. 0.5 is intentionally included.
DEFAULT_THRESHOLDS: tuple[float, ...] = tuple(round(i / 100.0, 2) for i in range(5, 100))

SELECTABLE_METRICS = ("f1", "precision", "recall")


@dataclass
class ThresholdCurvePoint:
    threshold: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    predicted_positive: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "predicted_positive": self.predicted_positive,
        }


@dataclass
class ThresholdSelection:
    """The threshold chosen on validation, with the evidence for the choice."""

    threshold: float
    metric: str
    validation_score: float | None
    curve: list[ThresholdCurvePoint] = field(default_factory=list)
    constraints: dict[str, float | None] = field(default_factory=dict)
    tie_break: str = "highest threshold among ties (fewest alerts)"
    data_used: str = "validation"

    def as_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "metric": self.metric,
            "validation_score": self.validation_score,
            "constraints": self.constraints,
            "tie_break": self.tie_break,
            "data_used": self.data_used,
            "curve": [p.as_dict() for p in self.curve],
        }


def threshold_curve(
    scores: Sequence[float],
    labels: Sequence[int],
    *,
    thresholds: Sequence[float] | None = None,
) -> list[ThresholdCurvePoint]:
    """Precision/recall/FPR at every candidate threshold (no selection)."""
    out: list[ThresholdCurvePoint] = []
    for t in thresholds or DEFAULT_THRESHOLDS:
        m = classification_metrics(list(scores), list(labels), threshold=t)
        out.append(
            ThresholdCurvePoint(
                threshold=round(float(t), 2),
                precision=m.get("precision") or 0.0,
                recall=m.get("recall") or 0.0,
                f1=m.get("f1") or 0.0,
                false_positive_rate=m.get("false_positive_rate") or 0.0,
                predicted_positive=int(m.get("tp", 0)) + int(m.get("fp", 0)),
            )
        )
    return out


def tune_threshold(
    validation_scores: Sequence[float],
    validation_labels: Sequence[int],
    *,
    metric: str = "f1",
    thresholds: Sequence[float] | None = None,
    min_precision: float | None = None,
    max_fpr: float | None = None,
) -> ThresholdSelection:
    """Select the operating threshold on the VALIDATION period only.

    Maximizes ``metric`` subject to optional constraints
    (``min_precision``, ``max_fpr``). Ties resolve to the highest threshold
    so the operating point errs toward fewer alerts. When no threshold
    satisfies the constraints the selection falls back to 0.5 and records
    that the constraints were unsatisfiable — it does not silently relax
    them.
    """
    if metric not in SELECTABLE_METRICS:
        raise ValueError(f"metric must be one of {SELECTABLE_METRICS}, got {metric!r}")

    curve = threshold_curve(validation_scores, validation_labels, thresholds=thresholds)
    feasible = [
        p for p in curve
        if (min_precision is None or p.precision >= min_precision)
        and (max_fpr is None or p.false_positive_rate <= max_fpr)
    ]
    constraints = {"min_precision": min_precision, "max_fpr": max_fpr}

    if not feasible:
        return ThresholdSelection(
            threshold=0.5,
            metric=metric,
            validation_score=None,
            curve=curve,
            constraints={**constraints, "satisfied": False},  # type: ignore[dict-item]
            data_used="validation (no feasible threshold; default 0.5)",
        )

    best_value = max(getattr(p, metric) for p in feasible)
    best = max(
        (p for p in feasible if getattr(p, metric) == best_value),
        key=lambda p: p.threshold,
    )
    return ThresholdSelection(
        threshold=best.threshold,
        metric=metric,
        validation_score=_r(getattr(best, metric)),
        curve=curve,
        constraints={**constraints, "satisfied": True},  # type: ignore[dict-item]
        data_used="validation",
    )


# ---------------------------------------------------------------------------
# split utilities + integrity
# ---------------------------------------------------------------------------

@dataclass
class RecordSplit:
    train: list[Any] = field(default_factory=list)
    validation: list[Any] = field(default_factory=list)
    test: list[Any] = field(default_factory=list)

    def as_dict(self) -> dict[str, int]:
        return {
            "train": len(self.train),
            "validation": len(self.validation),
            "test": len(self.test),
        }


def split_records(
    records: Sequence[Any],
    *,
    proportions: dict[str, float] | None = None,
) -> tuple[RecordSplit, TemporalSplit]:
    """Chronological train/validation/test split over labeled records.

    Returns both the record split (for convenience) and the underlying
    ``TemporalSplit`` (which carries the boundary timestamps).
    """
    ts = [r.session.end_time_epoch_ms or 0.0 for r in records]
    raw = temporal_split(list(records), timestamps=ts, proportions=proportions)
    return RecordSplit(train=raw.train, validation=raw.validation, test=raw.test), raw


def verify_split_integrity(split: TemporalSplit) -> dict[str, Any]:
    """Prove the three periods are disjoint and chronologically ordered.

    Returns a report with ``disjoint`` and ``chronological`` booleans plus
    the offending ids (empty when clean) so a test can assert on it.
    """

    def _id(item: Any) -> str:
        return getattr(item, "session_id", None) or getattr(item, "session", None).session_id

    def _end(item: Any) -> float:
        session = getattr(item, "session", item)
        return float(session.end_time_epoch_ms or 0.0)

    train_ids = {_id(r) for r in split.train}
    val_ids = {_id(r) for r in split.validation}
    test_ids = {_id(r) for r in split.test}
    overlaps = {
        "train_validation": sorted(train_ids & val_ids),
        "train_test": sorted(train_ids & test_ids),
        "validation_test": sorted(val_ids & test_ids),
    }
    chronological = True
    if split.train and split.validation:
        chronological &= max(_end(r) for r in split.train) <= min(_end(r) for r in split.validation)
    if split.validation and split.test:
        chronological &= max(_end(r) for r in split.validation) <= min(_end(r) for r in split.test)
    return {
        "disjoint": all(not v for v in overlaps.values()),
        "chronological": bool(chronological),
        "overlaps": overlaps,
        "counts": {
            "train": len(split.train),
            "validation": len(split.validation),
            "test": len(split.test),
        },
    }


# ---------------------------------------------------------------------------
# end-to-end tuning run
# ---------------------------------------------------------------------------

def _score_period(
    records: Sequence[Any],
    stack: ScoringStack,
) -> tuple[list[float], list[int], list[ScoredSession]]:
    scores: list[float] = []
    labels: list[int] = []
    scored: list[ScoredSession] = []
    for record in records:
        fset = record.session.session_features.get("_behavioral_feature_set")
        if fset is None:
            continue
        s = stack.score(fset)
        scored.append(s)
        scores.append(s.risk_score)
        labels.append(record.label)
    return scores, labels, scored


def run_threshold_tuning(
    records: Sequence[Any],
    stack: ScoringStack,
    *,
    proportions: dict[str, float] | None = None,
    metric: str = "f1",
    min_precision: float | None = None,
    max_fpr: float | None = None,
    seed: int = 42,
) -> dict[str, Any]:
    """Split, tune on validation, freeze, then score the test period once.

    The Isolation Forest (for C/D stacks) is fitted on benign training rows
    only. Validation picks the threshold. Test is evaluated at BOTH the
    selected threshold and the 0.5 default so the effect of tuning is
    visible rather than asserted.
    """
    split_records_list, temporal = split_records(records, proportions=proportions)
    integrity = verify_split_integrity(temporal)

    if stack.variant in ("C", "D"):
        benign_train = [
            r.session.session_features["_behavioral_feature_set"]
            for r in temporal.train
            if r.label == 0
            and r.session.session_features.get("_behavioral_feature_set") is not None
        ]
        model = fit_isolation_forest(benign_train, seed=seed, n_estimators=100, max_samples=64)
        if model is not None:
            stack.anomaly_model = model

    val_scores, val_labels, _ = _score_period(temporal.validation, stack)
    selection = tune_threshold(
        val_scores, val_labels,
        metric=metric, min_precision=min_precision, max_fpr=max_fpr,
    )

    test_scores, test_labels, test_scored = _score_period(temporal.test, stack)
    test_positives = sum(1 for y in test_labels if y == 1)
    test_negatives = len(test_labels) - test_positives

    return {
        "synthetic": True,
        "split_counts": split_records_list.as_dict(),
        "split_boundaries": temporal.boundaries,
        "split_integrity": integrity,
        "selection": selection.as_dict(),
        "validation_metrics": full_metrics(val_scores, val_labels, threshold=selection.threshold),
        "test_metrics_at_selected": full_metrics(test_scores, test_labels, threshold=selection.threshold),
        "test_metrics_at_default": full_metrics(test_scores, test_labels, threshold=0.5),
        "test_sample": {"positives": test_positives, "negatives": test_negatives},
        "note": (
            "Synthetic fixture with a small test sample. Extreme values "
            "(e.g. recall 1.0) are an artifact of sample size and the "
            "validation-tuned operating point, not a claim of perfect "
            "detection; the default 0.5 operating point is the headline."
        ),
        "seed": seed,
    }
