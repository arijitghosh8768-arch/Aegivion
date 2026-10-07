"""Recoverability analysis — **Part 2**.

Two distinct, independent questions:

1. **How much did this session destroy recovery state?**
   ``recovery_destruction_score`` — deterministic evidence strength from
   snapshot / backup-vault / recovery-point deletions (volume + pace,
   baseline-relative when a baseline exists, evidence-capped otherwise).

2. **Do recovery options remain available?**
   ``recoverability_score`` in ``[0, 1]`` — 1.0 means full recoverability
   (protected backups / versioning+lock still on), 0.0 means the session
   destroyed every recovery path it touched. Computed from observed
   protection state only; ``None`` when the evidence does not say.

3. **How much did this session weaken protection posture?**
   ``protection_degradation_score`` — protection changes, policy/share
   changes and protected deletions. Kept strictly **independent from
   actual data destruction**: it reflects posture changes only, never
   delete volume.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from algo.detection.cloud_destruction.baseline import BehaviorBaseline
from algo.detection.cloud_destruction.config import BehavioralConfig
from algo.detection.cloud_destruction.deviation import clamp01, hour_span, ratio_to_factor
from algo.detection.cloud_destruction.evidence import SessionEvidence, collect_evidence
from algo.detection.cloud_destruction.provenance import MeasuredValue
from algo.detection.cloud_destruction.schemas import DestructiveActivitySession, ResourceActivityEvent

__all__ = ["RecoverabilityAnalysis", "analyze_recoverability"]


@dataclass
class RecoverabilityAnalysis:
    """Deterministic recoverability features for one session."""

    recovery_destruction_score: Optional[MeasuredValue] = None
    protection_degradation_score: Optional[MeasuredValue] = None
    recoverability_score: Optional[MeasuredValue] = None


def analyze_recoverability(
    session: DestructiveActivitySession,
    baseline: Optional[BehaviorBaseline] = None,
    *,
    events: Optional[list[ResourceActivityEvent]] = None,
    config: Optional[BehavioralConfig] = None,
    evidence: Optional[SessionEvidence] = None,
) -> RecoverabilityAnalysis:
    """Compute recovery-destruction, protection-degradation and remaining
    recoverability for one session."""
    cfg = config or BehavioralConfig()
    ev = evidence or collect_evidence(session, events)
    result = RecoverabilityAnalysis()

    hours = hour_span(ev.event_count, ev.duration_seconds, cfg.min_session_seconds)
    contributors = ("recoverability",) + (("baseline",) if baseline is not None else ())

    recovery_impairing = ev.recovery_impairing_events
    vault_deletes = ev.backup_delete_events or 0
    rp_deletes = ev.recovery_point_delete_events or 0
    snapshot_deletes = ev.snapshot_delete_events or 0
    protection_changes = (ev.protection_change_events or 0) + (ev.policy_change_events or 0) + (
        ev.share_change_events or 0
    )

    # ---------------- recovery destruction (deletion of recovery state) -----
    if recovery_impairing == 0:
        result.recovery_destruction_score = MeasuredValue.measured(
            0.0,
            method="no_recovery_impairing_events",
            contributors=("recoverability",),
            raw={
                "snapshot_deletions": 0,
                "backup_deletions": 0,
                "recovery_point_deletions": 0,
            },
        )
    else:
        pace = recovery_impairing / hours if hours > 0 else float(recovery_impairing)
        if baseline is not None and baseline.delete_rate.mean is not None:
            deviation = ratio_to_factor(pace, baseline.delete_rate.mean, cfg.max_rate_deviation_factor)
            intensity = (
                deviation
                if deviation is not None
                else clamp01(recovery_impairing / max(1, cfg.recovery_score_count_cap))
            )
            method = "recovery_destruction_pace_ratio_to_factor"
            raw: dict[str, object] = {"normal_delete_per_hour": baseline.delete_rate.mean}
        else:
            intensity = clamp01(
                max(
                    recovery_impairing / max(1, cfg.recovery_score_count_cap),
                    pace / cfg.delete_burst_events_per_hour,
                )
            )
            method = "recovery_destruction_volume_and_pace_to_cap"
            raw = {}
        raw.update(
            {
                "snapshot_deletions": snapshot_deletes,
                "backup_deletions": vault_deletes,
                "recovery_point_deletions": rp_deletes,
                "protected_backup_deletions": ev.protected_backup_deletions,
                "protected_snapshot_deletions": ev.protected_snapshot_deletions,
                "critical_resource_touched": ev.critical_resource_touched,
                "duration_hours": hours,
            }
        )
        result.recovery_destruction_score = MeasuredValue.measured(
            intensity, method=method, contributors=contributors, raw=raw
        )

    # ---------------- protection degradation (posture changes only) ---------
    protected_deletions = ev.protected_backup_deletions + ev.protected_snapshot_deletions
    if (
        protection_changes == 0
        and protected_deletions == 0
    ):
        result.protection_degradation_score = MeasuredValue.measured(
            0.0,
            method="no_protection_changes",
            contributors=("protection",),
            raw={
                "protection_changes": 0,
                "policy_changes": 0,
                "share_changes": 0,
                "protected_deletions": 0,
            },
        )
    else:
        change_volume = protection_changes + 2 * protected_deletions
        result.protection_degradation_score = MeasuredValue.measured(
            clamp01(change_volume / max(1, cfg.protection_score_count_cap)),
            method="protection_change_volume_to_cap",
            contributors=("protection",),
            raw={
                "protection_changes": ev.protection_change_events or 0,
                "policy_changes": ev.policy_change_events or 0,
                "share_changes": ev.share_change_events or 0,
                "protected_backup_deletions": ev.protected_backup_deletions,
                "protected_snapshot_deletions": ev.protected_snapshot_deletions,
            },
        )

    # ---------------- remaining recoverability (protection state) -----------
    raw = {
        "recovery_impairing_events": recovery_impairing,
        "protected_backup_deletions": ev.protected_backup_deletions,
        "protected_snapshot_deletions": ev.protected_snapshot_deletions,
    }

    protected_paths = 0
    known_paths = 0
    if vault_deletes > 0 or rp_deletes > 0:
        known_paths += 1
        if ev.protected_backup_deletions < (vault_deletes + rp_deletes):
            # at least one unprotected deletion: remaining state unknown
            pass
        else:
            protected_paths += 1  # all deleted copies were protected
    if snapshot_deletes > 0:
        known_paths += 1
        if ev.protected_snapshot_deletions < snapshot_deletes:
            pass
        else:
            protected_paths += 1

    if known_paths > 0:
        # Deleting *protected* copies still leaves the protection layer; the
        # more unprotected copies were destroyed, the less recoverable.
        unprotected_ratio = 1.0 - (protected_paths / known_paths)
        score = clamp01(1.0 - unprotected_ratio)
        result.recoverability_score = MeasuredValue.measured(
            score,
            method="remaining_protection_paths",
            contributors=("recoverability",),
            raw={**raw, "protected_paths": protected_paths, "known_paths": known_paths},
        )
    elif ev.has_event_detail:
        result.recoverability_score = MeasuredValue.measured(
            1.0,
            method="no_recovery_state_touched",
            contributors=("recoverability",),
            raw=raw,
        )
    else:
        result.recoverability_score = MeasuredValue.unavailable(
            "protection_state_not_in_source", contributors=("recoverability",)
        )
    return result
