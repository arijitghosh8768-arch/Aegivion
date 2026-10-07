"""AWS Backup / recovery-point analysis — **Part 2**.

Analyzes backup-vault deletion, recovery-point deletion and backup-schedule
destruction against protection state and (when known) the actor's backup
history. Score outputs are deterministic evidence strengths in ``[0, 1]`` —
*not* risk verdicts — with raw counters attached for audit.

Features:

- ``backup_delete_score`` — vault/RP deletion intensity (volume + pace,
  baseline-relative when possible, evidence-capped otherwise);
- ``backup_anomaly`` — pace anomaly of all backup-family deletions vs the
  actor's deletion baseline;
- ``recovery_point_anomaly`` — breadth of distinct recovery points deleted
  vs the actor's normal resource scope.
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

__all__ = ["BackupAnalysis", "analyze_backup"]


@dataclass
class BackupAnalysis:
    """Deterministic backup/recovery features for one session."""

    backup_delete_score: Optional[MeasuredValue] = None
    backup_anomaly: Optional[MeasuredValue] = None
    recovery_point_anomaly: Optional[MeasuredValue] = None


def analyze_backup(
    session: DestructiveActivitySession,
    baseline: Optional[BehaviorBaseline],
    *,
    events: Optional[list[ResourceActivityEvent]] = None,
    config: Optional[BehavioralConfig] = None,
    evidence: Optional[SessionEvidence] = None,
) -> BackupAnalysis:
    """Analyze backup-vault and recovery-point destruction for one session."""
    cfg = config or BehavioralConfig()
    ev = evidence or collect_evidence(session, events)
    result = BackupAnalysis()

    hours = hour_span(ev.event_count, ev.duration_seconds, cfg.min_session_seconds)
    if hours <= 0:
        return result

    contributors = ("backup",) + (("baseline",) if baseline is not None else ())
    vault_deletes = ev.backup_delete_events or 0
    rp_deletes = ev.recovery_point_delete_events or 0
    family = vault_deletes + rp_deletes
    unique_rps = (
        ev.unique_recovery_points if ev.unique_recovery_points is not None else rp_deletes
    )
    unique_vaults = ev.unique_vaults if ev.unique_vaults is not None else vault_deletes

    if family == 0:
        result.backup_delete_score = MeasuredValue.measured(
            0.0,
            method="no_backup_deletions",
            contributors=("backup",),
            raw={"vault_deletions": 0, "recovery_point_deletions": 0},
        )
        result.backup_anomaly = MeasuredValue.unavailable(
            "no_backup_activity", contributors=("backup",)
        )
        result.recovery_point_anomaly = MeasuredValue.unavailable(
            "no_recovery_point_activity", contributors=("backup",)
        )
        return result

    pace = family / hours
    volume_raw = {
        "vault_deletions": vault_deletes,
        "recovery_point_deletions": rp_deletes,
        "unique_vaults": unique_vaults,
        "unique_recovery_points": unique_rps,
        "protected_backup_deletions": ev.protected_backup_deletions,
        "critical_resource_touched": ev.critical_resource_touched,
    }

    # intensity: baseline-relative when possible, else evidence-capped pace
    if baseline is not None and baseline.delete_rate.mean is not None:
        deviation = ratio_to_factor(pace, baseline.delete_rate.mean, cfg.max_rate_deviation_factor)
        intensity = (
            deviation
            if deviation is not None
            else clamp01(family / max(1, cfg.recovery_score_count_cap))
        )
        method = "backup_pace_ratio_to_factor"
        intensity_raw = {**volume_raw, "normal_delete_per_hour": baseline.delete_rate.mean}
    else:
        intensity = clamp01(
            max(
                family / max(1, cfg.recovery_score_count_cap),
                pace / cfg.delete_burst_events_per_hour,
            )
        )
        method = "backup_volume_and_pace_to_cap"
        intensity_raw = {**volume_raw, "observed_per_hour": pace}

    result.backup_delete_score = MeasuredValue.measured(
        intensity, method=method, contributors=contributors, raw=intensity_raw
    )

    # backup-family pace anomaly vs the actor's overall deletion baseline
    if baseline is not None and baseline.delete_rate.mean is not None:
        deviation = ratio_to_factor(pace, baseline.delete_rate.mean, cfg.ratio_deviation_factor)
        result.backup_anomaly = MeasuredValue.measured(
            deviation if deviation is not None else 0.0,
            method="backup_pace_ratio_to_factor",
            contributors=contributors,
            raw={**volume_raw, "observed_per_hour": pace},
        )
    else:
        result.backup_anomaly = absolute_pace_value(
            observed_per_hour=pace,
            cap_per_hour=cfg.delete_burst_events_per_hour,
            method="absolute_pace_to_cap",
            contributors=contributors,
            raw={**volume_raw, "observed_per_hour": pace},
        )

    # recovery-point breadth vs the actor's normal scope
    if unique_rps:
        if baseline is not None and baseline.unique_resources_per_hour.mean is not None:
            observed_scope = unique_rps / hours
            deviation = ratio_to_factor(
                observed_scope,
                baseline.unique_resources_per_hour.mean,
                cfg.scope_expansion_factor,
            )
            result.recovery_point_anomaly = MeasuredValue.measured(
                deviation if deviation is not None else 0.0,
                method="scope_ratio_to_factor",
                contributors=contributors,
                raw={"unique_recovery_points": unique_rps, "observed_per_hour": observed_scope},
            )
        else:
            result.recovery_point_anomaly = MeasuredValue.measured(
                clamp01(unique_rps / max(1, cfg.recovery_score_count_cap)),
                method="rp_breadth_to_cap",
                contributors=contributors,
                raw={"unique_recovery_points": unique_rps},
            )
    else:
        result.recovery_point_anomaly = MeasuredValue.unavailable(
            "no_recovery_point_activity", contributors=contributors
        )
    return result
