"""Snapshot analysis — **Part 2**.

Analyzes EBS/RDS snapshot deletion activity: volume, pacing, breadth, and
deletions of snapshots whose protection was known to be on. Score outputs
are deterministic evidence strengths in ``[0, 1]`` — *not* risk verdicts —
and always carry the raw counters they were computed from.

Features:

- ``snapshot_delete_score`` — deletion intensity (volume + pace, baseline-
  relative when a baseline exists, evidence-capped otherwise);
- ``snapshot_scope_anomaly`` — breadth of distinct snapshots deleted
  relative to the actor's normal resource scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from detection.cloud_destruction.baseline import BehaviorBaseline
from detection.cloud_destruction.config import BehavioralConfig
from detection.cloud_destruction.deviation import (
    absolute_pace_value,
    clamp01,
    hour_span,
    ratio_to_factor,
)
from detection.cloud_destruction.evidence import SessionEvidence, collect_evidence
from detection.cloud_destruction.provenance import MeasuredValue
from detection.cloud_destruction.schemas import DestructiveActivitySession, ResourceActivityEvent

__all__ = ["SnapshotAnalysis", "analyze_snapshots"]


@dataclass
class SnapshotAnalysis:
    """Deterministic snapshot features for one session."""

    snapshot_delete_score: Optional[MeasuredValue] = None
    snapshot_scope_anomaly: Optional[MeasuredValue] = None


def analyze_snapshots(
    session: DestructiveActivitySession,
    baseline: Optional[BehaviorBaseline],
    *,
    events: Optional[list[ResourceActivityEvent]] = None,
    config: Optional[BehavioralConfig] = None,
    evidence: Optional[SessionEvidence] = None,
) -> SnapshotAnalysis:
    """Analyze snapshot deletion intensity and scope for one session."""
    cfg = config or BehavioralConfig()
    ev = evidence or collect_evidence(session, events)
    result = SnapshotAnalysis()

    hours = hour_span(ev.event_count, ev.duration_seconds, cfg.min_session_seconds)
    if hours <= 0:
        return result

    contributors = ("snapshot",) + (("baseline",) if baseline is not None else ())
    snapshot_deletes = ev.snapshot_delete_events or 0
    unique_snapshots = ev.unique_snapshots if ev.unique_snapshots is not None else snapshot_deletes

    if snapshot_deletes == 0:
        result.snapshot_delete_score = MeasuredValue.measured(
            0.0,
            method="no_snapshot_deletions",
            contributors=("snapshot",),
            raw={"snapshot_delete_events": 0},
        )
        result.snapshot_scope_anomaly = MeasuredValue.unavailable(
            "no_snapshot_activity", contributors=("snapshot",)
        )
        return result

    volume_raw = {
        "snapshot_delete_events": snapshot_deletes,
        "ebs_snapshot_delete_events": ev.ebs_snapshot_delete_events or 0,
        "rds_snapshot_delete_events": ev.rds_snapshot_delete_events or 0,
        "unique_snapshots": unique_snapshots,
        "protected_snapshot_deletions": ev.protected_snapshot_deletions,
        "critical_resource_touched": ev.critical_resource_touched,
    }

    # intensity: baseline-relative when possible, else evidence-capped pace
    if baseline is not None and baseline.delete_rate.mean is not None:
        normal_share = baseline.delete_rate.mean
        deviation = ratio_to_factor(
            snapshot_deletes / hours, normal_share, cfg.max_rate_deviation_factor
        )
        intensity = (
            deviation
            if deviation is not None
            else clamp01(snapshot_deletes / max(1, cfg.snapshot_score_count_cap))
        )
        method = "snapshot_pace_ratio_to_factor"
        intensity_raw = {**volume_raw, "normal_delete_per_hour": normal_share}
    else:
        observed_pace = snapshot_deletes / hours
        intensity = clamp01(
            max(
                snapshot_deletes / max(1, cfg.snapshot_score_count_cap),
                observed_pace / cfg.delete_burst_events_per_hour,
            )
        )
        method = "snapshot_volume_and_pace_to_cap"
        intensity_raw = {**volume_raw, "observed_per_hour": observed_pace}

    # protected deletions are recorded in raw only — Part 3 decides weight
    result.snapshot_delete_score = MeasuredValue.measured(
        intensity,
        method=method,
        contributors=contributors,
        raw=intensity_raw,
    )

    # scope anomaly: distinct snapshots deleted vs the actor's normal breadth
    if baseline is not None and baseline.unique_resources_per_hour.mean is not None:
        observed_scope = unique_snapshots / hours
        deviation = ratio_to_factor(
            observed_scope,
            baseline.unique_resources_per_hour.mean,
            cfg.scope_expansion_factor,
        )
        result.snapshot_scope_anomaly = MeasuredValue.measured(
            deviation if deviation is not None else 0.0,
            method="scope_ratio_to_factor",
            contributors=contributors,
            raw={"unique_snapshots": unique_snapshots, "observed_per_hour": observed_scope},
        )
    else:
        result.snapshot_scope_anomaly = MeasuredValue.unavailable(
            "no_baseline", contributors=contributors
        )
    return result
