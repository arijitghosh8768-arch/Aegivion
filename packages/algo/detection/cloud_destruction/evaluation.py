"""Comparative evaluation framework — **Part 3** (+ final stage).

Compares detector variants on the same labeled session corpus:

0. ``deletion_threshold`` — **variant A**: a simple deletion-count
   threshold (the baseline the research question pits Aegivion
   against: fires when destructive deletions reach a fixed count);
1. ``rules_only``       — raw behavioral counters, no baselines, no ML;
2. ``rules_baseline``   — Part 2 baseline-relative deviations;
3. ``rules_sequence``   — + sequence transition model;
4. ``rules_baseline_ml``— + Isolation Forest;
5. ``full``             — all components (the Aegivion configuration).

Metrics per the Part 3 + final-stage spec: precision, recall, F1,
PR-AUC, ROC-AUC, false-positive rate, false-negative rate,
precision at the high-risk threshold, recall at a fixed FPR, and
detection latency / lead time (chronological-prefix re-detection).

**Label discipline**: corpora may be ``declared`` (real, reviewed) or
``synthetic`` (built from the synthetic fixtures). Results carry
``label_source``; synthetic results are never presented as production
performance. Labels attach to *sessions* via event ids, and only
sessions with both positive and negative examples produce meaningful
metrics — the framework refuses to report metrics from a degenerate
corpus rather than fabricating numbers.

**Threshold discipline** (final stage): thresholds are tuned on
TRAIN/VALIDATION splits only — never on the final TEST set — and the
split is temporal (past → train, later → validation, newest → test)
so no future telemetry leaks into threshold selection
(:func:`temporal_threshold_tuning`).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from algo.detection.cloud_destruction.config import DestructionDetectorConfig
from algo.detection.cloud_destruction.detector import DestructionDetector
from algo.detection.cloud_destruction.finding import SeverityPolicy
from algo.detection.cloud_destruction.schemas import (
    DestructiveActivitySession,
    ResourceActivityEvent,
)

__all__ = []  # set once at module end


@dataclass(frozen=True)
class LabeledCorpus:
    """A labeled corpus of canonical events (label provenance explicit)."""

    events: tuple[ResourceActivityEvent, ...]
    positive_event_ids: frozenset[str]
    negative_event_ids: frozenset[str]
    label_source: str
    """``"declared"`` or ``"synthetic"``."""
    description: str = ""

    def __post_init__(self) -> None:
        if self.label_source not in ("declared", "synthetic"):
            raise ValueError("label_source must be 'declared' or 'synthetic'")


@dataclass
class VariantResult:
    """Metrics for one detector variant on one corpus."""

    variant: str
    label_source: str
    n_sessions: int
    n_positives: int
    n_negatives: int
    threshold: float
    precision: float
    recall: float
    f1: float
    pr_auc: float
    roc_auc: float
    false_positive_rate: float
    false_negative_rate: float
    precision_at_high_risk: float
    recall_at_fixed_fpr: float
    latency_ms_per_session: float
    raw: dict[str, Any] = field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "variant": self.variant,
            "label_source": self.label_source,
            "n_sessions": self.n_sessions,
            "n_positives": self.n_positives,
            "n_negatives": self.n_negatives,
            "threshold": self.threshold,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "pr_auc": round(self.pr_auc, 4),
            "roc_auc": round(self.roc_auc, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "precision_at_high_risk": round(self.precision_at_high_risk, 4),
            "recall_at_fixed_fpr": round(self.recall_at_fixed_fpr, 4),
            "latency_ms_per_session": round(self.latency_ms_per_session, 3),
            "raw": dict(self.raw),
        }


#: The six mandated comparison variants: (name, kwargs for DestructionDetector).
#: ``deletion_threshold`` (variant A) is not a DestructionDetector — it is a
#: simple count comparator, special-cased in :func:`evaluate_variants`.
VARIANTS: dict[str, dict[str, bool]] = {
    "rules_only": {"use_ml": False, "use_sequence_model": False, "use_baseline": False},
    "rules_baseline": {"use_ml": False, "use_sequence_model": False, "use_baseline": True},
    "rules_sequence": {"use_ml": False, "use_sequence_model": True, "use_baseline": False},
    "rules_baseline_ml": {"use_ml": True, "use_sequence_model": False, "use_baseline": True},
    "full": {"use_ml": True, "use_sequence_model": True, "use_baseline": True},
}

#: Variant A's decision rule: fire when destructive deletion count
#: (deleted resources + version + snapshot + backup deletions) reaches
#: this count. Matches the behavioral mass-deletion category floor.
DELETION_COUNT_THRESHOLD: int = 5

#: "High-risk" threshold for precision-at-high-risk (SeverityPolicy band).
HIGH_RISK_THRESHOLD: float = SeverityPolicy().high_risk

#: Default FPR target for recall-at-fixed-FPR.
FIXED_FPR_TARGET: float = 0.05


def corpus_from_sessions(
    positive_sessions: Sequence,
    negative_sessions: Sequence,
    label_source: str = "synthetic",
    description: str = "",
) -> LabeledCorpus:
    """Build a labeled corpus from labeled session lists (with their events)."""
    positive_ids: set[str] = set()
    negative_ids: set[str] = set()
    events: list[ResourceActivityEvent] = []
    for session, events_for_session in positive_sessions:
        positive_ids.update(session.event_ids)
        events.extend(events_for_session)
    for session, events_for_session in negative_sessions:
        negative_ids.update(session.event_ids)
        events.extend(events_for_session)
    return LabeledCorpus(
        events=tuple(events),
        positive_event_ids=frozenset(positive_ids),
        negative_event_ids=frozenset(negative_ids),
        label_source=label_source,
        description=description,
    )


def _session_label(session, positive_ids: frozenset[str]) -> bool:
    """A session is positive if any of its events is labeled positive."""
    return any(eid in positive_ids for eid in session.event_ids)


def _deletion_count(session: DestructiveActivitySession) -> int:
    """Variant A's signal: total destructive deletion volume."""
    return (
        len(session.deleted_resources)
        + session.version_deletions
        + session.snapshot_deletions
        + session.backup_deletions
    )


def _pr_auc(scores: list[float], labels: list[bool]) -> float:
    """Average precision over the PR curve (ties grouped per threshold)."""
    total_pos = sum(1 for label in labels if label)
    if total_pos == 0 or not scores:
        return 0.0
    pairs = sorted(zip(scores, labels), key=lambda p: -p[0])
    tp = 0
    fp = 0
    auc = 0.0
    i = 0
    n = len(pairs)
    while i < n:
        threshold = pairs[i][0]
        # consume the whole tie group at this threshold
        while i < n and pairs[i][0] == threshold:
            if pairs[i][1]:
                tp += 1
            else:
                fp += 1
            i += 1
        recall = tp / total_pos
        precision = tp / (tp + fp)
        auc += recall * precision  # Δrecall × precision for this block
    return max(0.0, min(1.0, auc))


def _roc_auc(scores: list[float], labels: list[bool]) -> float:
    """ROC-AUC via trapezoidal integration over tie-grouped TPR/FPR points."""
    total_pos = sum(1 for label in labels if label)
    total_neg = sum(1 for label in labels if not label)
    if total_pos == 0 or total_neg == 0 or not scores:
        return 0.0
    pairs = sorted(zip(scores, labels), key=lambda p: -p[0])
    fpr_points = [0.0]
    tpr_points = [0.0]
    tp = 0
    fp = 0
    i = 0
    n = len(pairs)
    while i < n:
        threshold = pairs[i][0]
        while i < n and pairs[i][0] == threshold:
            if pairs[i][1]:
                tp += 1
            else:
                fp += 1
            i += 1
        tpr_points.append(tp / total_pos)
        fpr_points.append(fp / total_neg)
    tpr_points.append(1.0)
    fpr_points.append(1.0)
    auc = 0.0
    for k in range(1, len(fpr_points)):
        width = fpr_points[k] - fpr_points[k - 1]
        auc += width * (tpr_points[k] + tpr_points[k - 1]) / 2.0
    return max(0.0, min(1.0, auc))


def _confusion(scores: list[float], labels: list[bool], threshold: float) -> tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for score, label in zip(scores, labels):
        predicted = score >= threshold
        if predicted and label:
            tp += 1
        elif predicted and not label:
            fp += 1
        elif not predicted and not label:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn


def _precision_at_high_risk(
    scores: list[float], labels: list[bool], high_threshold: float
) -> float:
    """Precision among sessions scoring at/above the high-risk threshold."""
    tp = fp = 0
    for score, label in zip(scores, labels):
        if score >= high_threshold:
            if label:
                tp += 1
            else:
                fp += 1
    return tp / (tp + fp) if (tp + fp) else 0.0


def _recall_at_fixed_fpr(
    scores: list[float], labels: list[bool], target_fpr: float
) -> float:
    """Maximum recall achievable without exceeding the target FPR."""
    total_pos = sum(1 for label in labels if label)
    total_neg = sum(1 for label in labels if not label)
    if total_pos == 0 or total_neg == 0 or not scores:
        return 0.0
    best = 0.0
    for threshold in sorted(set(scores), reverse=True):
        tp = fp = 0
        for score, label in zip(scores, labels):
            if score >= threshold:
                if label:
                    tp += 1
                else:
                    fp += 1
        fpr = fp / total_neg
        if fpr <= target_fpr:
            best = max(best, tp / total_pos)
    return best


def measure_detection_latency(
    detector: DestructionDetector,
    events: Sequence[ResourceActivityEvent],
    *,
    positive_event_ids: frozenset[str],
    threshold: float = 0.35,
) -> dict[str, Any]:
    """Detection latency + lead time via chronological-prefix re-detection.

    For every session that contains positive-labeled events, the
    detector is re-run on each chronological prefix of the stream
    (all events received up to that timestamp — streaming semantics).
    The earliest prefix at which the session's finding crosses
    ``threshold`` is the detection point:

    - ``detection_latency_seconds``: session start → detection point;
    - ``lead_time_seconds``: detection point → session end (how much
      of the attack remained unseen at detection time; a *negative*
      value would mean detection after the session ended).

    Sessions that never cross the threshold are reported as
    undetected (``None``) — never counted as zero-latency detections.

    Scope note: this measurement is *scenario-local replay* (the same
    scope the ReplayEngine uses) so that prefix re-detection stays
    tractable; baselines are rebuilt from the scenario's own history.
    """
    ordered = sorted(events, key=lambda e: e.timestamp)
    full = detector.detect(list(ordered))

    # sessions of interest: those containing positive-labeled events
    tracked: dict[str, set[str]] = {}
    for session in full.sessions:
        hits = {eid for eid in session.event_ids if eid in positive_event_ids}
        if hits:
            tracked[session.session_id] = set(session.event_ids)

    records: list[dict[str, Any]] = []
    for session in full.sessions:
        if session.session_id not in tracked:
            continue
        start = session.start_time
        end = session.end_time or start
        fired_at: Optional[ResourceActivityEvent] = None
        for k in range(1, len(ordered) + 1):
            prefix = ordered[:k]
            outcome = detector.detect(list(prefix))
            for candidate in outcome.sessions:
                if not candidate.event_ids:
                    continue
                overlap = tracked[session.session_id] & set(candidate.event_ids)
                if not overlap:
                    continue
                finding = next(
                    (f for f in outcome.findings if f.session_id == candidate.session_id),
                    None,
                )
                if finding is not None and finding.risk_score >= threshold:
                    fired_at = prefix[-1]
                    break
            if fired_at is not None:
                break
        record: dict[str, Any] = {
            "session_actor": session.actor_id,
            "session_events": session.event_count,
            "detected": fired_at is not None,
        }
        if fired_at is not None and start is not None and end is not None:
            # ``fired_at`` is the triggering *event*; its ``timestamp``
            # attribute is the datetime of detection.
            detected_at = fired_at.timestamp
            record["detection_latency_seconds"] = (
                detected_at.timestamp() - start.timestamp()
            )
            record["lead_time_seconds"] = (
                end.timestamp() - detected_at.timestamp()
            )
        else:
            record["detection_latency_seconds"] = None
            record["lead_time_seconds"] = None
        records.append(record)

    detected = [r for r in records if r["detected"]]
    latencies = [r["detection_latency_seconds"] for r in detected]
    lead_times = [r["lead_time_seconds"] for r in detected]

    def _mean(values: list[float]) -> Optional[float]:
        return sum(values) / len(values) if values else None

    return {
        "method": "chronological_prefix_redetection",
        "scope": "scenario-local replay",
        "threshold": threshold,
        "n_tracked_sessions": len(records),
        "n_detected": len(detected),
        "per_session": records,
        "mean_detection_latency_seconds": _mean(latencies),
        "median_detection_latency_seconds": (
            sorted(latencies)[len(latencies) // 2] if latencies else None
        ),
        "mean_lead_time_seconds": _mean(lead_times),
        "median_lead_time_seconds": (
            sorted(lead_times)[len(lead_times) // 2] if lead_times else None
        ),
    }


@dataclass
class ThresholdTuningResult:
    """Temporal TRAIN/VALIDATION/TEST threshold tuning (no test leakage)."""

    tuned_threshold: float
    thresholds_evaluated: list[float]
    validation_f1: dict[str, float]
    train_metrics: dict[str, float]
    validation_metrics: dict[str, float]
    test_metrics: dict[str, float]
    split: dict[str, dict[str, Any]]
    raw: dict[str, Any] = field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "tuned_threshold": self.tuned_threshold,
            "thresholds_evaluated": list(self.thresholds_evaluated),
            "validation_f1": {k: round(v, 4) for k, v in self.validation_f1.items()},
            "train_metrics": self.train_metrics,
            "validation_metrics": self.validation_metrics,
            "test_metrics": self.test_metrics,
            "split": self.split,
        }


def _chunk_metrics(
    scores: list[float], labels: list[bool], threshold: float
) -> dict[str, float]:
    tp, fp, tn, fn = _confusion(scores, labels, threshold)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "n_sessions": len(scores),
    }


def temporal_threshold_tuning(
    corpus: LabeledCorpus,
    *,
    config: Optional[DestructionDetectorConfig] = None,
    anomaly_seed: int = 1337,
    grid: Optional[Sequence[float]] = None,
) -> ThresholdTuningResult:
    """Temporal threshold tuning: past → TRAIN, later → VALIDATION, newest → TEST.

    The detector is unsupervised — nothing is fitted on TRAIN; the
    split governs *threshold selection* only. The threshold grid is
    evaluated on VALIDATION F1 (the best F1 wins; ties break toward
    the highest — most conservative — threshold) and the tuned
    threshold is reported once on TEST. TEST is never inspected
    during selection.
    """
    thresholds = sorted(grid) if grid is not None else [
        round(0.05 * i, 2) for i in range(1, 20)
    ]
    config = config or DestructionDetectorConfig()
    detector = DestructionDetector(config, anomaly_seed=anomaly_seed)
    outcome = detector.detect(list(corpus.events))

    findings_by_session = {f.session_id: f for f in outcome.findings}
    sessions = sorted(
        outcome.sessions,
        key=lambda s: (s.start_time or s.end_time or datetime.min.replace(tzinfo=timezone.utc)),
    )
    scores = [
        findings_by_session[s.session_id].risk_score
        if s.session_id in findings_by_session
        else 0.0
        for s in sessions
    ]
    labels = [_session_label(s, corpus.positive_event_ids) for s in sessions]

    # contiguous temporal thirds
    n = len(sessions)
    train_end = n // 3
    validation_end = (2 * n) // 3
    splits = {
        "train": (slice(0, train_end), "oldest third"),
        "validation": (slice(train_end, validation_end), "middle third"),
        "test": (slice(validation_end, n), "newest third"),
    }

    def _slice_scores(name: str) -> tuple[list[float], list[bool]]:
        sl, _ = splits[name]
        return scores[sl], labels[sl]

    # threshold selection on VALIDATION only
    val_scores, val_labels = _slice_scores("validation")
    validation_f1: dict[str, float] = {}
    best_threshold = thresholds[0]
    best_f1 = -1.0
    for threshold in thresholds:
        metrics = _chunk_metrics(val_scores, val_labels, threshold)
        validation_f1[f"{threshold:.2f}"] = metrics["f1"]
        # tie-break: highest threshold with maximal validation F1
        if metrics["f1"] > best_f1 or (
            metrics["f1"] == best_f1 and threshold > best_threshold
        ):
            best_f1 = metrics["f1"]
            best_threshold = threshold

    train_metrics = _chunk_metrics(*_slice_scores("train"), best_threshold)
    validation_metrics = _chunk_metrics(val_scores, val_labels, best_threshold)
    test_metrics = _chunk_metrics(*_slice_scores("test"), best_threshold)

    return ThresholdTuningResult(
        tuned_threshold=best_threshold,
        thresholds_evaluated=list(thresholds),
        validation_f1=validation_f1,
        train_metrics=train_metrics,
        validation_metrics=validation_metrics,
        test_metrics=test_metrics,
        split={
            name: {
                "n_sessions": len(scores[sl]),
                "n_positives": sum(1 for label in labels[sl] if label),
                "time_range": [
                    sessions[sl.start].start_time.isoformat() if sessions[sl.start].start_time else None,
                    sessions[sl.stop - 1].end_time.isoformat() if sessions[sl.stop - 1].end_time else None,
                ],
                "rule": rule,
            }
            for name, (sl, rule) in splits.items()
        },
        raw={
            "selection_rule": "max validation F1; ties break to highest threshold",
            "test_touched_during_selection": False,
            "label_source": corpus.label_source,
        },
    )


def evaluate_variants(
    corpus: LabeledCorpus,
    *,
    config: Optional[DestructionDetectorConfig] = None,
    threshold: float = 0.35,
    anomaly_seed: int = 1337,
    high_risk_threshold: float = HIGH_RISK_THRESHOLD,
    fixed_fpr_target: float = FIXED_FPR_TARGET,
) -> dict[str, VariantResult]:
    """Run all six variants over the corpus and compare.

    Returns per-variant metrics; refuses degenerate corpora (all-positive
    or all-negative) with ``ValueError`` instead of fabricating numbers.
    """
    config = config or DestructionDetectorConfig()
    results: dict[str, VariantResult] = {}
    positive_ids = corpus.positive_event_ids
    negative_ids = corpus.negative_event_ids

    # Degenerate-corpus guard (counts only; session ids are per-run uuids,
    # so labels are recomputed inside each variant run below).
    reference = DestructionDetector(config)
    reference_outcome = reference.detect(list(corpus.events))
    n_pos = sum(
        1
        for s in reference_outcome.sessions
        if any(eid in positive_ids for eid in s.event_ids)
    )
    n_neg = len(reference_outcome.sessions) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError(
            "degenerate corpus: need both positive and negative sessions; "
            f"got {n_pos} positive / {n_neg} negative"
        )

    # ---- Variant A: deletion-count threshold (not a detector) ----------
    labels = [
        any(eid in positive_ids for eid in s.event_ids)
        for s in reference_outcome.sessions
    ]
    deletion_counts = [_deletion_count(s) for s in reference_outcome.sessions]
    # ranking score for PR/ROC curves: count normalized by the threshold
    scores_a = [min(1.0, count / DELETION_COUNT_THRESHOLD) for count in deletion_counts]
    predictions_a = [count >= DELETION_COUNT_THRESHOLD for count in deletion_counts]
    tp = sum(1 for p, label in zip(predictions_a, labels) if p and label)
    fp = sum(1 for p, label in zip(predictions_a, labels) if p and not label)
    fn = sum(1 for p, label in zip(predictions_a, labels) if not p and label)
    tn = sum(1 for p, label in zip(predictions_a, labels) if not p and not label)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    results["deletion_threshold"] = VariantResult(
        variant="deletion_threshold",
        label_source=corpus.label_source,
        n_sessions=len(reference_outcome.sessions),
        n_positives=n_pos,
        n_negatives=n_neg,
        threshold=float(DELETION_COUNT_THRESHOLD),
        precision=precision,
        recall=recall,
        f1=f1,
        pr_auc=_pr_auc(scores_a, labels),
        roc_auc=_roc_auc(scores_a, labels),
        false_positive_rate=fp / (fp + tn) if (fp + tn) else 0.0,
        false_negative_rate=fn / (fn + tp) if (fn + tp) else 0.0,
        precision_at_high_risk=_precision_at_high_risk(
            scores_a, labels, high_risk_threshold
        ),
        recall_at_fixed_fpr=_recall_at_fixed_fpr(scores_a, labels, fixed_fpr_target),
        latency_ms_per_session=0.0,
        raw={
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "description": corpus.description,
            "synthetic_labels": corpus.label_source == "synthetic",
            "decision_rule": (
                "deleted_resources + version_deletions + snapshot_deletions "
                f"+ backup_deletions >= {DELETION_COUNT_THRESHOLD}"
            ),
            "deletion_counts": deletion_counts,
        },
    )

    for name, flags in VARIANTS.items():
        detector = DestructionDetector(config, anomaly_seed=anomaly_seed, **flags)
        started = time.perf_counter()
        outcome = detector.detect(list(corpus.events))
        elapsed = time.perf_counter() - started

        # Labels are computed from THIS run's sessions (session ids are
        # per-run uuids; sessionization content is deterministic).
        findings_by_session = {f.session_id: f for f in outcome.findings}
        labels = [
            any(eid in positive_ids for eid in s.event_ids)
            for s in outcome.sessions
        ]
        scores = [
            findings_by_session[s.session_id].risk_score
            if s.session_id in findings_by_session
            else 0.0
            for s in outcome.sessions
        ]

        tp, fp, tn, fn = _confusion(scores, labels, threshold)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        fnr = fn / (fn + tp) if (fn + tp) else 0.0
        pr_auc = _pr_auc(scores, labels)
        roc_auc = _roc_auc(scores, labels)
        latency = (elapsed * 1000.0) / max(1, len(outcome.sessions))

        results[name] = VariantResult(
            variant=name,
            label_source=corpus.label_source,
            n_sessions=len(outcome.sessions),
            n_positives=n_pos,
            n_negatives=n_neg,
            threshold=threshold,
            precision=precision,
            recall=recall,
            f1=f1,
            pr_auc=pr_auc,
            roc_auc=roc_auc,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            precision_at_high_risk=_precision_at_high_risk(
                scores, labels, high_risk_threshold
            ),
            recall_at_fixed_fpr=_recall_at_fixed_fpr(scores, labels, fixed_fpr_target),
            latency_ms_per_session=latency,
            raw={
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "description": corpus.description,
                "synthetic_labels": corpus.label_source == "synthetic",
            },
        )
    return results


__all__ = [
    "DELETION_COUNT_THRESHOLD",
    "FIXED_FPR_TARGET",
    "HIGH_RISK_THRESHOLD",
    "LabeledCorpus",
    "ThresholdTuningResult",
    "VariantResult",
    "VARIANTS",
    "corpus_from_sessions",
    "evaluate_variants",
    "measure_detection_latency",
    "temporal_threshold_tuning",
]
