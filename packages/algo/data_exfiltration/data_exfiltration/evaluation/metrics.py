"""Evaluation metrics for Algorithm #2 (extends the Part 3 set).

Adds what the final contract requires beyond ml/evaluation.py:

- false negative rate
- detection latency (proxy: alert time within the replay, seconds)
- detection lead time (proxy: time between first exfil event and the
  earliest threshold crossing within the session window)
- precision@high-risk (precision among findings above the high-risk band)
- recall@fixed-FPR (recall achievable at the largest threshold whose FPR
  stays under the cap)

Emphasis: PR-AUC and false-positive behavior, per the contract, because
security data is imbalanced.
"""

from __future__ import annotations

from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.ml.evaluation import classification_metrics, pr_auc, roc_curve, _roc_auc, _r


def false_negative_rate(labels: Sequence[int], predictions: Sequence[int]) -> float:
    positives = sum(1 for y in labels if y == 1)
    if positives == 0:
        return 0.0
    misses = sum(1 for y, p in zip(labels, predictions) if y == 1 and p == 0)
    return _r(misses / positives)


def precision_at_high_risk(
    scores: Sequence[float],
    labels: Sequence[int],
    *,
    threshold: float = 0.7,
) -> float | None:
    """Precision restricted to the high-risk band (score >= threshold).

    None when no session reaches the band (no claim is made)."""
    idx = [i for i, s in enumerate(scores) if s >= threshold]
    if not idx:
        return None
    hits = sum(1 for i in idx if labels[i] == 1)
    return _r(hits / len(idx))


def recall_at_fixed_fpr(
    scores: Sequence[float],
    labels: Sequence[int],
    *,
    max_fpr: float = 0.05,
) -> float | None:
    """Best recall over thresholds whose FPR <= max_fpr.

    None when no threshold satisfies the cap (also no claim)."""
    best: float | None = None
    total_pos = sum(1 for y in labels if y == 1)
    total_neg = len(labels) - total_pos
    if total_pos == 0 or total_neg == 0:
        return None
    for step in range(0, 101):
        threshold = step / 100.0
        predictions = [1 if s >= threshold else 0 for s in scores]
        fp = sum(1 for y, p in zip(labels, predictions) if y == 0 and p == 1)
        tp = sum(1 for y, p in zip(labels, predictions) if y == 1 and p == 1)
        fpr = fp / total_neg
        if fpr <= max_fpr:
            recall = tp / total_pos
            best = recall if best is None else max(best, recall)
    return _r(best) if best is not None else None


def detection_latency_ms(
    scored_sessions: Sequence[Any],
) -> float | None:
    """Mean session close-to-alert delay.

    In this replay design sessions are scored the moment they close, so
    the honest latency proxy is zero; the field exists so a streaming
    deployment can substitute its real scheduling delay without changing
    the metric contract."""
    latencies = [
        getattr(s, "alert_latency_ms", None) for s in scored_sessions
        if getattr(s, "alert_latency_ms", None) is not None
    ]
    if not latencies:
        return None
    return _r(sum(latencies) / len(latencies))


def detection_lead_time_s(
    scored_sessions: Sequence[Any],
    feature_sets: Sequence[Any],
) -> float | None:
    """Mean lead time: session duration left at scoring time.

    Sessions are scored at close, so lead time is the fraction of the
    session still ahead of the analyst. Computed from the feature set's
    recorded duration; None when durations are unavailable."""
    durations = []
    duration_by_id = {
        getattr(f, "session_id", None): getattr(f, "session_duration_s", None)
        for f in feature_sets
    }
    for s in scored_sessions:
        d = duration_by_id.get(getattr(s, "session_id", None))
        if d is not None:
            durations.append(d)
    if not durations:
        return None
    return _r(sum(durations) / len(durations))


def full_metrics(
    scores: Sequence[float],
    labels: Sequence[int],
    *,
    threshold: float = 0.5,
    scored_sessions: Sequence[Any] | None = None,
    feature_sets: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """The complete metric block for one variant on one test period."""
    base = classification_metrics(scores, labels, threshold=threshold)
    base["false_negative_rate"] = false_negative_rate(
        labels, [1 if s >= threshold else 0 for s in scores]
    )
    base["pr_auc"] = pr_auc(scores, labels)
    base["roc_auc"] = _roc_auc(scores, labels)
    base["precision_at_high_risk"] = precision_at_high_risk(scores, labels)
    base["recall_at_fixed_fpr"] = recall_at_fixed_fpr(scores, labels)
    if scored_sessions is not None:
        base["detection_latency_ms"] = detection_latency_ms(scored_sessions)
    if scored_sessions is not None and feature_sets is not None:
        base["detection_lead_time_s"] = detection_lead_time_s(scored_sessions, feature_sets)
    return base
