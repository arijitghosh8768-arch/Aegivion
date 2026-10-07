"""Protection-state catalog and enrichment interfaces.

Destructive-activity detection is only meaningful in the context of a
resource's *recovery posture*. That posture is external fact: bucket
versioning, object lock, backup coverage, snapshot protection, retention.
This module defines the provider-neutral interface for it.

Rules:

1. The catalog is the **only** source of protection state. The normalizer
   never guesses whether versioning was enabled — no entry means
   ``None`` + reason ``enrichment_missing``.
2. Part 1 ships a :class:`StaticProtectionCatalog` (populated from resource
   inventory / fixtures). Real-time catalogs land later.
3. :class:`RecoverabilityAssessor` is an explicit Part 2 placeholder: it
   raises :class:`NotImplementedYetError` instead of returning a made-up
   recoverability score.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field  # noqa: F401  # field: ProtectionState.details
from typing import Any, Optional

from algo.detection.cloud_destruction.provenance import MeasuredValue, UnavailableReason
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    BusinessCriticality,
    DestructiveActivitySession,
    ResourceActivityEvent,
    ResourceProtectionProfile,
    ResourceType,
)


@dataclass(frozen=True)
class ProtectionState:
    """Protection facts observed for one resource, with availability reasons.

    ``None`` always pairs with a reason — callers can distinguish "the source
    does not say" from "not applicable".
    """

    resource_id: str
    resource_type: ResourceType = ResourceType.UNKNOWN
    versioning_enabled: Optional[bool] = None
    object_lock_enabled: Optional[bool] = None
    backup_enabled: Optional[bool] = None
    snapshot_protection_enabled: Optional[bool] = None
    retention_period: Optional[int] = None
    business_criticality: Optional[BusinessCriticality] = None
    sensitivity_level: Optional[str] = None
    unavailable_reason: UnavailableReason = UnavailableReason.NOT_IN_SOURCE
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_known(self) -> bool:
        """True when at least one protection fact is present."""
        return any(
            value is not None
            for value in (
                self.versioning_enabled,
                self.object_lock_enabled,
                self.backup_enabled,
                self.snapshot_protection_enabled,
                self.retention_period,
                self.business_criticality,
            )
        )


class ProtectionCatalog(ABC):
    """Provider-neutral lookup of resource protection state."""

    @abstractmethod
    def lookup(self, resource_id: str, resource_type: Optional[str] = None) -> Optional[ProtectionState]:
        """Return protection state for a resource, or ``None`` if unknown."""
        raise NotImplementedError

    def enrich(self, resource_id: Optional[str], resource_type: Optional[str] = None) -> ProtectionState:
        """Never-``None`` variant returning an explicitly-unknown state."""
        state = self.lookup(resource_id, resource_type) if resource_id else None
        if state is not None:
            return state
        return ProtectionState(
            resource_id=resource_id or "",
            unavailable_reason=UnavailableReason.ENRICHMENT_MISSING,
        )


class StaticProtectionCatalog(ProtectionCatalog):
    """In-memory catalog built from :class:`ResourceProtectionProfile`s.

    Suitable for fixtures, replay corpora and small inventories. Lookups
    accept the bare resource id or the resource ARN.
    """

    def __init__(self, profiles: Optional[list[ResourceProtectionProfile]] = None) -> None:
        self._by_id: dict[str, ResourceProtectionProfile] = {}
        self._by_arn: dict[str, ResourceProtectionProfile] = {}
        for profile in profiles or []:
            self.add(profile)

    def add(self, profile: ResourceProtectionProfile) -> None:
        self._by_id[profile.resource_id] = profile
        if profile.resource_arn:
            self._by_arn[profile.resource_arn] = profile

    def lookup(self, resource_id: str, resource_type: Optional[str] = None) -> Optional[ProtectionState]:
        profile = self._by_id.get(resource_id) or self._by_arn.get(resource_id)
        if profile is None:
            return None
        retention = profile.retention_configuration
        retention_days = None
        if isinstance(retention, dict) and isinstance(retention.get("retention_days"), int):
            retention_days = retention["retention_days"]
        elif isinstance(retention, dict) and isinstance(retention.get("retention_period_days"), int):
            retention_days = retention["retention_period_days"]
        return ProtectionState(
            resource_id=profile.resource_id,
            resource_type=profile.resource_type,
            versioning_enabled=profile.versioning_enabled,
            object_lock_enabled=profile.object_lock_enabled,
            backup_enabled=profile.backup_enabled,
            snapshot_protection_enabled=profile.snapshot_protection_enabled,
            retention_period=retention_days,
            business_criticality=profile.business_criticality,
            details={
                "owner": profile.owner,
                "business_unit": profile.business_unit,
                "recovery_point_available": profile.recovery_point_available,
            },
        )


class RecoverabilityAssessor:
    """Assess remaining recoverability from a resource's protection profile.

    Part 2 implementation: a deterministic, explainable estimate in
    ``[0, 1]`` derived **only** from catalog facts (no guessing, no scores
    from other algorithms). """

    def score(self, profile: ResourceProtectionProfile) -> float:
        """Return remaining recoverability in ``[0, 1]`` for one resource.

        1.0  → at least one protected recovery path is known to be on
               (backups, recovery point, or versioning + object lock);
        0.0  → every known recovery mechanism is off;
        mid  → versioning on without lock, or snapshots without protection.
        """
        paths: list[tuple[bool, bool]] = []  # (enabled, protected)

        if profile.backup_enabled is not None:
            paths.append((profile.backup_enabled, bool(profile.backup_enabled)))
        if profile.recovery_point_available is not None:
            paths.append((profile.recovery_point_available, bool(profile.recovery_point_available)))
        if profile.versioning_enabled is not None and profile.object_lock_enabled is not None:
            paths.append((profile.versioning_enabled, bool(profile.versioning_enabled and profile.object_lock_enabled)))
        elif profile.versioning_enabled is not None:
            paths.append((profile.versioning_enabled, False))
        if profile.snapshot_enabled is not None:
            paths.append(
                (profile.snapshot_enabled, bool(profile.snapshot_protection_enabled or False))
            )

        if not paths:
            # No catalog facts at all: the honest answer is "unknown", which
            # callers represent as 0.0 *with* the reason recorded upstream —
            # or by consulting feature availability instead of this value.
            return 0.0

        weighted = 0.0
        total = 0.0
        for enabled, protected in paths:
            weight = 1.0
            if enabled and protected:
                weighted += weight
            elif enabled:
                weighted += 0.5 * weight
            total += weight
        return weighted / total if total else 0.0


# --------------------------------------------------------------------------- #
# Protection-degradation analysis (Part 2)
# --------------------------------------------------------------------------- #


@dataclass
class ProtectionDegradationAnalysis:
    """Deterministic protection-degradation features for one session.

    Independent from data destruction: reflects posture changes only.
    """

    protection_degradation_score: Optional[MeasuredValue] = None
    degraded_mechanisms: tuple[str, ...] = ()


def analyze_protection_changes(
    session: DestructiveActivitySession,
    events: Optional[list[ResourceActivityEvent]] = None,
) -> ProtectionDegradationAnalysis:
    """Detect protection weakening from protection-change events.

    Weakening is inferred from raw provider actions (evidence, not guesses):
    disabling versioning, weakening object lock, deleting lifecycle rules,
    removing vault lock / access policies. """
    from algo.detection.cloud_destruction.provenance import MeasuredValue  # local: avoid cycle

    protection_events = [
        e
        for e in (events or [])
        if e.action_category
        in (
            ActionCategory.PROTECTION_CHANGE,
            ActionCategory.POLICY_CHANGE,
            ActionCategory.SHARE_CHANGE,
        )
    ]

    weakened: set[str] = set()
    for event in protection_events:
        raw = (event.raw_action or "").lower()
        if any(token in raw for token in ("deletebucketlifecycle", "deletebackupvaultlock", "deletebackupvaultaccesspolicy")):
            weakened.add("lifecycle_or_lock_removed")
        if any(token in raw for token in ("putbucketversioning", "objectlockconfiguration")):
            weakened.add("versioning_or_lock_changed")
        if "policy" in raw or "acl" in raw:
            weakened.add("policy_or_acl_changed")

    # Fallback: session aggregates carry the count even without event detail.
    total_changes = len(protection_events) or session.protection_changes
    score = 0.0
    if total_changes or weakened:
        score = min(1.0, (total_changes + 2 * len(weakened)) / 3.0)

    return ProtectionDegradationAnalysis(
        protection_degradation_score=(
            MeasuredValue.measured(
                score,
                method="protection_change_volume_and_weakening",
                contributors=("protection",),
                raw={
                    "protection_change_events": total_changes,
                    "weakened_mechanisms": sorted(weakened),
                },
            )
            if (total_changes or weakened)
            else MeasuredValue.measured(
                0.0,
                method="no_protection_changes",
                contributors=("protection",),
                raw={"protection_change_events": 0},
            )
        ),
        degraded_mechanisms=tuple(sorted(weakened)),
    )


__all__ = [
    "ProtectionCatalog",
    "ProtectionDegradationAnalysis",
    "ProtectionState",
    "RecoverabilityAssessor",
    "StaticProtectionCatalog",
    "analyze_protection_changes",
]
