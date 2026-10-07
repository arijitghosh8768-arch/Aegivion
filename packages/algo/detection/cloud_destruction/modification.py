"""Modification intelligence — **Part 2**.

Compares a session's write / modify / rewrite activity and resource scope
against the actor's baseline. Legitimate systems modify a lot — so a high
volume alone is never a signal; the deviation is always relative to *this
actor's* trusted history, with raw counters attached for audit.

All values follow the shared deviation semantics (see
:mod:`detection.cloud_destruction.deviation`): ``0.0`` at/below normal,
``1.0`` at/above the configured factor over normal, ``None`` when no
baseline evidence exists (never silently zero).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from algo.detection.cloud_destruction.baseline import BehaviorBaseline
from algo.detection.cloud_destruction.config import BehavioralConfig
from algo.detection.cloud_destruction.deviation import hour_span, ratio_to_factor
from algo.detection.cloud_destruction.evidence import SessionEvidence, collect_evidence
from algo.detection.cloud_destruction.provenance import MeasuredValue
from algo.detection.cloud_destruction.schemas import DestructiveActivitySession, ResourceActivityEvent

__all__ = ["ModificationAnalysis", "analyze_modification"]


@dataclass
class ModificationAnalysis:
    """Deterministic modification-side features for one session."""

    write_rate_deviation: Optional[MeasuredValue] = None
    modify_rate_deviation: Optional[MeasuredValue] = None
    rewrite_rate_deviation: Optional[MeasuredValue] = None
    resource_scope_deviation: Optional[MeasuredValue] = None
    object_count_deviation: Optional[MeasuredValue] = None


def _rate(
    count: Optional[int],
    evidence: SessionEvidence,
    cfg: BehavioralConfig,
) -> Optional[float]:
    """Events per hour with a duration floor; ``None`` stays ``None``."""
    if count is None:
        return None
    hours = hour_span(evidence.event_count, evidence.duration_seconds, cfg.min_session_seconds)
    if hours <= 0:
        return None
    return count / hours


def analyze_modification(
    session: DestructiveActivitySession,
    baseline: Optional[BehaviorBaseline],
    *,
    events: Optional[list[ResourceActivityEvent]] = None,
    config: Optional[BehavioralConfig] = None,
    evidence: Optional[SessionEvidence] = None,
) -> ModificationAnalysis:
    """Compare one session's modification activity to the actor's baseline."""
    cfg = config or BehavioralConfig()
    ev = evidence or collect_evidence(session, events)
    result = ModificationAnalysis()

    hours = hour_span(ev.event_count, ev.duration_seconds, cfg.min_session_seconds)
    if hours <= 0:
        return result

    contributors = ("modification",) + (("baseline",) if baseline is not None else ())

    def rate_value(count: Optional[int], normal, method: str) -> MeasuredValue:
        if count is None:
            return MeasuredValue.unavailable(
                "event_detail_missing" if not ev.has_event_detail else "unavailable",
                contributors=contributors,
            )
        observed = count / hours
        deviation = ratio_to_factor(observed, normal, cfg.max_rate_deviation_factor)
        raw = {"observed_per_hour": observed, "count": count, "duration_hours": hours}
        if deviation is None:
            value = MeasuredValue.unavailable("no_baseline", contributors=contributors)
        else:
            value = MeasuredValue.measured(
                deviation, method=method, contributors=contributors, raw=raw
            )
        value.raw.update(raw)
        return value

    if baseline is not None:
        result.write_rate_deviation = rate_value(
            ev.write_events, baseline.write_rate.mean, "rate_ratio_to_factor"
        )
        result.modify_rate_deviation = rate_value(
            ev.modify_events, baseline.modify_rate.mean, "rate_ratio_to_factor"
        )
        result.rewrite_rate_deviation = rate_value(
            ev.rewrite_events, baseline.rewrite_rate.mean, "rate_ratio_to_factor"
        )

        observed_scope = float(ev.unique_resource_count) / hours
        scope_dev = ratio_to_factor(
            observed_scope,
            baseline.unique_resources_per_hour.mean,
            cfg.max_rate_deviation_factor,
        )
        scope_raw = {
            "unique_resources": ev.unique_resource_count,
            "observed_per_hour": observed_scope,
        }
        if scope_dev is None:
            result.resource_scope_deviation = MeasuredValue.unavailable(
                "no_baseline", contributors=contributors
            )
        else:
            result.resource_scope_deviation = MeasuredValue.measured(
                scope_dev,
                method="scope_ratio_to_factor",
                contributors=contributors,
                raw=scope_raw,
            )

        if ev.max_object_count is None or baseline.object_count.mean is None:
            result.object_count_deviation = MeasuredValue.unavailable(
                "object_count_not_in_source"
                if ev.max_object_count is None
                else "no_baseline",
                contributors=contributors,
            )
        else:
            count_dev = ratio_to_factor(
                float(ev.max_object_count),
                baseline.object_count.mean,
                cfg.object_count_deviation_factor,
            )
            result.object_count_deviation = MeasuredValue.measured(
                count_dev if count_dev is not None else 0.0,
                method="object_count_ratio_to_factor",
                contributors=contributors,
                raw={"max_object_count": ev.max_object_count, "normal_mean": baseline.object_count.mean},
            )
    else:
        no_baseline = MeasuredValue.unavailable("no_baseline", contributors=("modification",))
        result.write_rate_deviation = (
            MeasuredValue.unavailable("event_detail_missing", contributors=("modification",))
            if ev.write_events is None
            else no_baseline
        )
        result.modify_rate_deviation = (
            MeasuredValue.unavailable("event_detail_missing", contributors=("modification",))
            if ev.modify_events is None
            else no_baseline
        )
        result.rewrite_rate_deviation = no_baseline
        result.resource_scope_deviation = no_baseline
        result.object_count_deviation = MeasuredValue.unavailable(
            "object_count_not_in_source", contributors=("modification",)
        )
    return result
