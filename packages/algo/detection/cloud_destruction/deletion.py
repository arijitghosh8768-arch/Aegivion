"""Deletion intelligence — **Part 2**.

Deletion-volume analysis against the actor's baseline: rate deviation,
delete-ratio anomaly and deletion-scope anomaly. "Many deletes" is *not*
automatically malicious — every value is relative to this actor's trusted
history and always accompanied by raw counters for audit.

Deviation semantics: ``0.0`` at/below normal, ``1.0`` at/above the
configured factor over normal, ``None`` when no baseline evidence exists
(never silently zero). The raw counters ride along on every value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from detection.cloud_destruction.baseline import BehaviorBaseline
from detection.cloud_destruction.config import BehavioralConfig
from detection.cloud_destruction.deviation import hour_span, ratio_to_factor
from detection.cloud_destruction.evidence import SessionEvidence, collect_evidence
from detection.cloud_destruction.provenance import MeasuredValue
from detection.cloud_destruction.schemas import DestructiveActivitySession, ResourceActivityEvent

__all__ = ["DeletionAnalysis", "analyze_deletion"]


@dataclass
class DeletionAnalysis:
    """Deterministic deletion-side features for one session."""

    delete_rate_deviation: Optional[MeasuredValue] = None
    delete_ratio_anomaly: Optional[MeasuredValue] = None
    deletion_scope_anomaly: Optional[MeasuredValue] = None
    delete_count: int = 0
    delete_rate_per_hour: Optional[float] = None
    unique_deleted_resources: int = 0


def analyze_deletion(
    session: DestructiveActivitySession,
    baseline: Optional[BehaviorBaseline],
    *,
    events: Optional[list[ResourceActivityEvent]] = None,
    config: Optional[BehavioralConfig] = None,
    evidence: Optional[SessionEvidence] = None,
) -> DeletionAnalysis:
    """Compare one session's deletion activity to the actor's baseline."""
    cfg = config or BehavioralConfig()
    ev = evidence or collect_evidence(session, events)
    result = DeletionAnalysis()

    hours = hour_span(ev.event_count, ev.duration_seconds, cfg.min_session_seconds)
    if hours <= 0:
        return result

    contributors = ("deletion",) + (("baseline",) if baseline is not None else ())

    # Aggregate mode: Part 1 sessions do not carry a plain-delete counter.
    # Derive a documented *lower bound* from the destructive counter:
    # destructive = delete + version + snapshot + backup/RP + modify
    # + rewrite + protection, so destructive - rewrite - protection counts
    # plain deletes plus modifies (unknown without event detail).
    aggregate_family = (
        (ev.version_delete_events or 0)
        + (ev.snapshot_delete_events or 0)
        + (ev.backup_delete_events or 0)
    )
    derived_lower = max(
        aggregate_family,
        ev.destructive_event_count
        - (ev.rewrite_events or 0)
        - (ev.protection_change_events or 0),
    )
    delete_family = (
        ev.delete_family_events
        if ev.delete_family_events is not None
        else max(0, derived_lower)
    )
    result.delete_count = delete_family
    result.delete_rate_per_hour = delete_family / hours
    result.unique_deleted_resources = ev.unique_resource_count if delete_family else 0

    observed_rate = delete_family / hours  # lower bound in aggregate mode
    raw = {
        "delete_family_events": delete_family,
        "observed_per_hour": observed_rate,
        "duration_hours": hours,
        "unique_deleted_resources": result.unique_deleted_resources,
    }

    if baseline is not None and baseline.delete_rate.mean is not None:
        deviation = ratio_to_factor(
            observed_rate, baseline.delete_rate.mean, cfg.max_rate_deviation_factor
        )
        result.delete_rate_deviation = MeasuredValue.measured(
            deviation if deviation is not None else 0.0,
            method="rate_ratio_to_factor",
            contributors=contributors,
            raw={**raw, "normal_delete_per_hour": baseline.delete_rate.mean},
        )
    else:
        result.delete_rate_deviation = MeasuredValue.unavailable(
            "no_baseline", contributors=contributors
        )
        result.delete_rate_deviation.raw.update(raw)

    # delete-ratio anomaly: share of the session that was deletion-family
    observed_ratio = (
        delete_family / ev.event_count if ev.event_count else None
    )
    ratio_raw = {
        "delete_family_events": delete_family,
        "event_count": ev.event_count,
        "observed_delete_ratio": observed_ratio,
    }
    if observed_ratio is None:
        result.delete_ratio_anomaly = MeasuredValue.unavailable(
            "empty_session", contributors=contributors
        )
        result.delete_ratio_anomaly.raw.update(ratio_raw)
    elif baseline is not None and baseline.delete_ratio.mean is not None:
        deviation = ratio_to_factor(
            observed_ratio, baseline.delete_ratio.mean, cfg.ratio_deviation_factor
        )
        result.delete_ratio_anomaly = MeasuredValue.measured(
            deviation if deviation is not None else 0.0,
            method="ratio_ratio_to_factor",
            contributors=contributors,
            raw={**ratio_raw, "normal_delete_ratio": baseline.delete_ratio.mean},
        )
    else:
        result.delete_ratio_anomaly = MeasuredValue.unavailable(
            "no_baseline", contributors=contributors
        )
        result.delete_ratio_anomaly.raw.update(ratio_raw)

    # deletion-scope anomaly: breadth of distinct targets touched by deletes
    scope_raw = {
        "unique_resources_touched": ev.unique_resource_count,
        "delete_family_events": delete_family,
    }
    if baseline is not None and baseline.unique_resources_per_hour.mean is not None:
        observed_scope = ev.unique_resource_count / hours
        deviation = ratio_to_factor(
            observed_scope,
            baseline.unique_resources_per_hour.mean,
            cfg.scope_expansion_factor,
        )
        result.deletion_scope_anomaly = MeasuredValue.measured(
            deviation if deviation is not None else 0.0,
            method="scope_ratio_to_factor",
            contributors=contributors,
            raw={**scope_raw, "observed_per_hour": observed_scope},
        )
    else:
        result.deletion_scope_anomaly = MeasuredValue.unavailable(
            "no_baseline", contributors=contributors
        )
        result.deletion_scope_anomaly.raw.update(scope_raw)
    return result
