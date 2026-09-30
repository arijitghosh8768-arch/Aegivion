"""Approved-activity profiles: scoped, auditable, reversible exceptions.

A large transfer is not automatically exfiltration. Nightly backups,
warehouse exports, ETL pipelines, analytics workloads, approved
migrations, scheduled reports, disaster recovery, and known SaaS
transfers can all look like exfiltration to a volume-only lens.

Rules enforced by this module:

1. **Never silently suppress.** Matching a profile never deletes or
   downgrades a finding by itself; it records an auditable exception
   record on the validation outcome. The validator decides what to do
   with it, and the record stays.
2. **Scoped.** A profile matches specific actors (or actor patterns),
   specific resources (or prefixes), specific destinations, and
   optionally the action kinds it covers. An exception that matches
   "everything" is rejected at registration time.
3. **Reversible.** Profiles carry ``enabled`` and ``expires_at_epoch_ms``.
   Disabling or expiring one immediately returns behavior to full
   scrutiny; the audit trail keeps the history.
4. **Time-aware.** Profiles can be restricted to explicit UTC hour
   windows and weekdays (e.g. the 01:00-03:00 backup window). Activity
   outside the window does NOT match the profile — a backup running at
   14:00 deserves review.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Sequence

from pydantic import BaseModel, Field


class ApprovedActivityKind(str, Enum):
    """The exception categories the contract requires explicitly."""

    BACKUP_JOB = "backup_job"
    WAREHOUSE_EXPORT = "data_warehouse_export"
    ETL_PIPELINE = "etl_pipeline"
    ANALYTICS_WORKLOAD = "analytics_workload"
    APPROVED_MIGRATION = "approved_migration"
    SCHEDULED_REPORT = "scheduled_report"
    DISASTER_RECOVERY = "disaster_recovery"
    KNOWN_SAAS_TRANSFER = "known_saas_transfer"


APPROVED_ACTIVITY_KINDS = tuple(k.value for k in ApprovedActivityKind)


class ApprovedActivityProfile(BaseModel):
    """One scoped, time-bounded, reversible exception definition."""

    profile_id: str
    name: str
    kind: ApprovedActivityKind

    actors: list[str] = Field(default_factory=list)
    """Exact actor ids (ARNs) this profile covers."""
    actor_patterns: list[str] = Field(default_factory=list)
    """fnmatch patterns over actor ids (e.g. ``arn:aws:sts::*:assumed-role/BackupOperator/*``)."""
    resources: list[str] = Field(default_factory=list)
    """Exact resource ids (``s3://bucket``) covered."""
    resource_prefixes: list[str] = Field(default_factory=list)
    """Resource id prefixes covered (e.g. ``s3://backups-``)."""
    destinations: list[str] = Field(default_factory=list)
    """Explicitly allowed destination IPs/domains (empty = destinations unconstrained)."""

    min_bytes: float | None = None
    """Lower volume bound the profile is trusted for; None = no constraint."""
    max_bytes: float | None = None
    """Upper volume bound; activity beyond it does NOT match (oversized
    'backups' deserve review). None = no constraint."""

    start_hour_utc: int | None = None
    end_hour_utc: int | None = None
    """Inclusive start, exclusive end UTC hours; may wrap midnight. None = all hours."""
    days_of_week: frozenset[int] | None = None
    """0=Monday .. 6=Sunday; None = every day."""

    enabled: bool = True
    """Reversibility switch: False immediately withdraws the exception."""
    expires_at_epoch_ms: float | None = None
    """Time-boxed approvals expire; expired profiles stop matching."""
    reason: str | None = None
    approver: str | None = None
    created_at_epoch_ms: float | None = None

    def content_hash(self) -> str:
        blob = json.dumps(self.model_dump(mode="json"), sort_keys=True, default=str).encode()
        return "aap-" + hashlib.sha256(blob).hexdigest()[:12]

    # ------------------------------------------------------------------
    # matching helpers
    # ------------------------------------------------------------------

    def _actor_matches(self, actor_id: str | None) -> bool:
        if not self.actors and not self.actor_patterns:
            return False  # a profile without actor scope is not registered
        if actor_id is None:
            return False
        if actor_id in self.actors:
            return True
        return any(fnmatch.fnmatchcase(actor_id, pat) for pat in self.actor_patterns)

    def _resource_matches(self, resource_id: str | None) -> bool:
        if not self.resources and not self.resource_prefixes:
            return False  # a profile without resource scope is not registered
        if resource_id is None:
            return False
        if resource_id in self.resources:
            return True
        return any(resource_id.startswith(p) for p in self.resource_prefixes)

    def _destination_matches(self, destinations: Sequence[str]) -> bool:
        if not self.destinations:
            return True  # unconstrained: profile does not claim destinations
        allowed = set(self.destinations)
        return bool(destinations) and all(d in allowed for d in destinations)

    def _volume_matches(self, bytes_total: float | None) -> bool:
        if bytes_total is None:
            return True  # volume absent -> volume does not disqualify the match
        if self.min_bytes is not None and bytes_total < self.min_bytes:
            return False
        if self.max_bytes is not None and bytes_total > self.max_bytes:
            return False
        return True

    def _time_matches(self, when: datetime) -> bool:
        if self.days_of_week is not None and when.weekday() not in self.days_of_week:
            return False
        if self.start_hour_utc is None and self.end_hour_utc is None:
            return True
        start = self.start_hour_utc
        end = self.end_hour_utc
        if start is None:
            start = end
        if end is None:
            end = start
        hour = when.hour
        if start == end:
            return hour == start  # single-hour window
        if start < end:
            return start <= hour < end
        return hour >= start or hour < end  # wraps midnight

    def _valid_now(self, when: datetime) -> bool:
        if not self.enabled:
            return False
        if self.expires_at_epoch_ms is not None:
            if when.timestamp() * 1000.0 >= self.expires_at_epoch_ms:
                return False
        return True


class ExceptionRecord(BaseModel):
    """The auditable trail of one profile evaluated against one finding.

    ``matched`` records what happened; profiles that did NOT match also
    produce records with the reason — nothing is ever silent.
    """

    record_id: str
    profile_id: str
    profile_name: str
    kind: str
    matched: bool
    reason: str
    evaluation_epoch_ms: float
    profile_hash: str
    scope: dict[str, Any] = Field(default_factory=dict)
    """Snapshot of the profile scope at evaluation time (audit needs the
    exact exception that was in force, not today's version)."""


class ApprovedActivityRegistry:
    """Holds approved profiles; every evaluation produces records."""

    def __init__(self, profiles: Sequence[ApprovedActivityProfile] | None = None) -> None:
        self._profiles: dict[str, ApprovedActivityProfile] = {}
        for profile in profiles or []:
            self.register(profile)

    # ------------------------------------------------------------------

    def register(self, profile: ApprovedActivityProfile) -> None:
        """Register a profile; rejects exceptions that are not scoped."""
        if not (profile.actors or profile.actor_patterns):
            raise ValueError(
                f"profile {profile.profile_id!r} has no actor scope; "
                "unscoped exceptions are not allowed"
            )
        if not (profile.resources or profile.resource_prefixes):
            raise ValueError(
                f"profile {profile.profile_id!r} has no resource scope; "
                "unscoped exceptions are not allowed"
            )
        self._profiles[profile.profile_id] = profile

    def remove(self, profile_id: str) -> bool:
        """Revoke a profile (reversibility). History stays in audit logs."""
        return self._profiles.pop(profile_id, None) is not None

    def disable(self, profile_id: str) -> bool:
        profile = self._profiles.get(profile_id)
        if profile is None:
            return False
        profile.enabled = False
        return True

    def enable(self, profile_id: str) -> bool:
        profile = self._profiles.get(profile_id)
        if profile is None:
            return False
        profile.enabled = True
        return True

    @property
    def profiles(self) -> list[ApprovedActivityProfile]:
        return list(self._profiles.values())

    def __len__(self) -> int:
        return len(self._profiles)

    # ------------------------------------------------------------------

    def evaluate(
        self,
        *,
        actor_id: str | None,
        resources: Sequence[str],
        destinations: Sequence[str],
        bytes_total: float | None,
        at_epoch_ms: float | None = None,
    ) -> list[ExceptionRecord]:
        """Evaluate every registered profile; return records for ALL of them.

        Every candidate profile yields a record — matched or not — so the
        audit trail shows which exceptions were considered and why each
        did or did not apply.
        """
        evaluation_ms = at_epoch_ms if at_epoch_ms is not None else _utcnow_ms()
        when = datetime.fromtimestamp(evaluation_ms / 1000.0, tz=timezone.utc)
        records: list[ExceptionRecord] = []

        for profile in self._profiles.values():
            matched, reason = self._match(
                profile, actor_id, resources, destinations, bytes_total, when
            )
            records.append(
                ExceptionRecord(
                    record_id=f"aap-{uuid.uuid4().hex[:12]}",
                    profile_id=profile.profile_id,
                    profile_name=profile.name,
                    kind=profile.kind.value,
                    matched=matched,
                    reason=reason,
                    evaluation_epoch_ms=evaluation_ms,
                    profile_hash=profile.content_hash(),
                    scope={
                        "actors": list(profile.actors),
                        "actor_patterns": list(profile.actor_patterns),
                        "resources": list(profile.resources),
                        "resource_prefixes": list(profile.resource_prefixes),
                        "destinations": list(profile.destinations),
                        "window_hours_utc": (
                            None
                            if profile.start_hour_utc is None and profile.end_hour_utc is None
                            else [profile.start_hour_utc, profile.end_hour_utc]
                        ),
                        "days_of_week": sorted(profile.days_of_week) if profile.days_of_week else None,
                        "max_bytes": profile.max_bytes,
                        "enabled": profile.enabled,
                        "expires_at_epoch_ms": profile.expires_at_epoch_ms,
                    },
                )
            )
        return records

    @staticmethod
    def _match(
        profile: ApprovedActivityProfile,
        actor_id: str | None,
        resources: Sequence[str],
        destinations: Sequence[str],
        bytes_total: float | None,
        when: datetime,
    ) -> tuple[bool, str]:
        if not profile._valid_now(when):
            return False, (
                "profile disabled" if not profile.enabled else "profile expired"
            )
        if not profile._actor_matches(actor_id):
            return False, "actor outside profile scope"
        if not any(
            profile._resource_matches(r) for r in resources
        ) and resources:
            return False, "resources outside profile scope"
        if not resources and not profile._resource_matches(None):
            return False, "session has no identifiable resource"
        if not profile._destination_matches(destinations):
            return False, "destination outside profile allow-list"
        if not profile._volume_matches(bytes_total):
            if profile.max_bytes is not None and bytes_total is not None and bytes_total > profile.max_bytes:
                return False, "volume above profile ceiling (oversized transfer)"
            return False, "volume below profile floor"
        if not profile._time_matches(when):
            return False, "outside approved time window"
        return True, "activity within profile scope"


def _utcnow_ms() -> float:
    return datetime.now(timezone.utc).timestamp() * 1000.0
