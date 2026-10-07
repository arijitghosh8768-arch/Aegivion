"""Version-destruction analysis — **Part 2**.

Differentiates ordinary object deletion from *specific version deletion*
on versioned buckets. A rapid rise in version deletions is a distinct
signal: it consumes recovery history one version at a time.

Features:

- ``version_delete_anomaly`` — baseline deviation of the version-deletion
  pace; falls back to an explicitly-configured absolute pace cap when no
  baseline exists (raw counters always attached);
- ``version_deletion_ratio`` — version deletes as a share of the whole
  deletion family, compared against the actor's normal mix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from detection.cloud_destruction.baseline import BehaviorBaseline
from detection.cloud_destruction.config import BehavioralConfig
from detection.cloud_destruction.deviation import (
    absolute_pace_value,
    hour_span,
    ratio_to_factor,
)
from detection.cloud_destruction.evidence import SessionEvidence, collect_evidence
from detection.cloud_destruction.provenance import MeasuredValue
from detection.cloud_destruction.schemas import DestructiveActivitySession, ResourceActivityEvent

__all__ = ["VersioningAnalysis", "analyze_versioning"]


@dataclass
class VersioningAnalysis:
    """Deterministic version-destruction features for one session."""

    version_delete_anomaly: Optional[MeasuredValue] = None
    version_deletion_ratio: Optional[MeasuredValue] = None


def analyze_versioning(
    session: DestructiveActivitySession,
    baseline: Optional[BehaviorBaseline],
    *,
    events: Optional[list[ResourceActivityEvent]] = None,
    config: Optional[BehavioralConfig] = None,
    evidence: Optional[SessionEvidence] = None,
) -> VersioningAnalysis:
    """Analyze version-deletion intensity and mix for one session."""
    cfg = config or BehavioralConfig()
    ev = evidence or collect_evidence(session, events)
    result = VersioningAnalysis()

    hours = hour_span(ev.event_count, ev.duration_seconds, cfg.min_session_seconds)
    if hours <= 0:
        return result

    contributors = ("versioning",) + (("baseline",) if baseline is not None else ())
    version_deletes = ev.version_delete_events or 0
    # Distinct keys are only known with event detail — never guessed.
    unique_versions = len(ev.version_deletes_per_key) if ev.version_deletes_per_key else None
    # The version-mix denominator is the whole deletion family, including
    # plain deletes (aggregate mode: documented lower bound, see deletion.py).
    version_component = (
        ev.version_delete_events or 0
    ) + (ev.snapshot_delete_events or 0) + (ev.backup_delete_events or 0)
    derived_lower = max(
        version_component,
        ev.destructive_event_count
        - (ev.rewrite_events or 0)
        - (ev.protection_change_events or 0),
    )
    delete_family = (
        ev.delete_family_events
        if ev.delete_family_events is not None
        else derived_lower
    )

    pace_raw = {
        "version_delete_events": version_deletes,
        "unique_keys_targeted": unique_versions,
        "duration_hours": hours,
        "version_deletes_per_key": dict(ev.version_deletes_per_key),
    }

    # 1) pace deviation vs baseline; absolute-pace fallback without baseline
    if baseline is not None and baseline.version_delete_ratio.evidence > 0:
        normal_pace = None
        if baseline.delete_rate.mean is not None and baseline.version_delete_ratio.mean is not None:
            normal_pace = baseline.delete_rate.mean * baseline.version_delete_ratio.mean
        deviation = ratio_to_factor(
            version_deletes / hours, normal_pace, cfg.max_rate_deviation_factor
        )
        if deviation is None:
            result.version_delete_anomaly = MeasuredValue.unavailable(
                "no_baseline", contributors=contributors
            )
        else:
            result.version_delete_anomaly = MeasuredValue.measured(
                deviation,
                method="version_pace_ratio_to_factor",
                contributors=contributors,
                raw={**pace_raw, "normal_pace_per_hour": normal_pace},
            )
    else:
        observed_pace = version_deletes / hours
        result.version_delete_anomaly = absolute_pace_value(
            observed_per_hour=observed_pace,
            cap_per_hour=cfg.version_burst_events_per_hour,
            method="absolute_pace_to_cap",
            contributors=contributors,
            raw={**pace_raw, "observed_per_hour": observed_pace, "cap_per_hour": cfg.version_burst_events_per_hour},
        )

    # 2) version share of the deletion family vs the actor's normal mix
    observed_ratio = (
        version_deletes / delete_family if delete_family else None
    )
    ratio_raw = {
        "version_delete_events": version_deletes,
        "delete_family_events": delete_family,
        "observed_ratio": observed_ratio,
    }
    if observed_ratio is None:
        result.version_deletion_ratio = MeasuredValue.unavailable(
            "no_deletion_family_events", contributors=contributors
        )
    elif baseline is not None and baseline.version_delete_ratio.mean is not None:
        deviation = ratio_to_factor(
            observed_ratio, baseline.version_delete_ratio.mean, cfg.ratio_deviation_factor
        )
        result.version_deletion_ratio = MeasuredValue.measured(
            deviation if deviation is not None else 0.0,
            method="mix_ratio_to_factor",
            contributors=contributors,
            raw={**ratio_raw, "normal_ratio": baseline.version_delete_ratio.mean},
        )
    else:
        result.version_deletion_ratio = MeasuredValue.measured(
            observed_ratio,
            method="observed_mix_ratio",
            contributors=contributors,
            raw=ratio_raw,
        )
    return result
