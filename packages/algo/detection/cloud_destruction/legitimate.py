"""Legitimate-activity context — **Part 2**.

Builds explicit support for benign mass-activity patterns: lifecycle
cleanup, scheduled maintenance, backup retention, CI/CD deployment,
database maintenance, migration, batch processing and temporary-resource
cleanup. Legitimacy is expressed as **declarative, auditable
:class:`ApprovedActivityProfile` objects** — never as a blanket whitelist
of actors and never as invented risk scores.

Rules:

- **Auditable**: every profile has a stable id, a version and a
  ``justification``; every evaluation records *which* profile matched and
  which constraints matched (kept on :class:`ActivityContext`).
- **Scoped**: matching is constrained by actor, resource ids, resource
  types, operations, account/region, and a coarse time window.
- **Reversible**: profiles can be disabled/revoked at any time
  (``enabled=False``); nothing destructive is ever authorized — this layer
  only annotates *evidence* with legitimate-activity context.
- **Time-aware**: optional ``hours_start``/``hours_end`` (UTC, inclusive
  start, exclusive end) and an optional ``valid_until`` expiry.

An ``ApprovedActivityProfile`` never fabricates availability: features
remain ``None`` when evidence is missing. Approval does **not** remove
sessions from baseline-poisoning classification (HIGH/CRITICAL history is
never automatically trusted).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from detection.cloud_destruction.schemas import (
    ActionCategory,
    CloudProvider,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

__all__ = ["ActivityContext", "ApprovedActivityProfile", "match_profile"]


class ActivityContext(BaseModel):
    """Legitimate-activity annotation attached to a feature vector.

    Immutable value object; produced deterministically from the session
    plus the declared approved profiles.
    """

    model_config = ConfigDict(frozen=True)

    approved: bool = False
    profile_id: Optional[str] = None
    profile_version: Optional[str] = None
    justification: Optional[str] = None
    matched_constraints: tuple[str, ...] = Field(default_factory=tuple)
    """Which profile constraints matched (actor/resource/operation/window)."""
    expired: bool = False
    """Profile matched but its validity window has passed."""


@dataclass(frozen=True)
class ApprovedActivityProfile:
    """A declared, auditable pattern of legitimate mass activity.

    Every field is an explicit scope constraint; all declared constraints
    must match for the profile to apply. Declare only what you can defend
    in an audit — each profile carries a version and a justification.
    """

    profile_id: str
    activity: str
    """One of: lifecycle_cleanup, scheduled_maintenance, backup_retention,
    cicd_deployment, database_maintenance, migration, batch_processing,
    temporary_resource_cleanup."""
    version: str = "1"
    justification: str = ""
    enabled: bool = True

    # scope constraints — all declared constraints must match
    actor_ids: frozenset[str] = frozenset()
    account_ids: frozenset[str] = frozenset()
    resource_ids: frozenset[str] = frozenset()
    resource_types: frozenset[str] = frozenset()
    operations: frozenset[str] = frozenset()
    """Canonical :class:`ActionCategory` values the profile covers."""
    provider: Optional[CloudProvider] = None
    hours_start: Optional[int] = None
    """UTC hour (0-23), inclusive."""
    hours_end: Optional[int] = None
    """UTC hour (0-23), exclusive."""
    valid_until: Optional[object] = None
    """Aware datetime after which the profile is expired (time-aware)."""

    def _matches(
        self,
        session: DestructiveActivitySession,
        events: Sequence[ResourceActivityEvent],
    ) -> Optional[tuple[str, ...]]:
        """Return matched constraint names, or ``None`` when no match."""
        matched: list[str] = []

        if self.actor_ids:
            if session.actor_id not in self.actor_ids:
                return None
            matched.append("actor")

        if self.account_ids:
            if session.account_id not in self.account_ids:
                return None
            matched.append("account")

        if self.resource_ids:
            touched = {r for r in session.resources_touched if r}
            if not touched or not touched.issubset(self.resource_ids):
                return None
            matched.append("resource")

        if self.operations:
            categories = {e.action_category.value for e in events}
            if not events or not categories.issubset(self.operations):
                return None
            matched.append("operations")

        if self.resource_types:
            types = {e.resource_type.value for e in events}
            if not events or not types.issubset(self.resource_types):
                return None
            matched.append("resource_types")

        if self.provider is not None and session.provider is not self.provider:
            return None
        if self.provider is not None:
            matched.append("provider")

        if self.hours_start is not None and self.hours_end is not None:
            times = [e.timestamp for e in events] or (
                [t for t in (session.start_time, session.end_time) if t is not None]
            )
            if not times:
                return None
            for ts in times:
                hour = ts.hour
                if self.hours_start <= self.hours_end:
                    if not (self.hours_start <= hour < self.hours_end):
                        return None
                else:  # window wraps midnight
                    if not (hour >= self.hours_start or hour < self.hours_end):
                        return None
            matched.append("time_window")

        if self.valid_until is not None:
            reference = events[0].timestamp if events else session.start_time
            if reference is not None and reference > self.valid_until:
                return None
            matched.append("validity")

        return tuple(matched)

    def match(
        self,
        session: DestructiveActivitySession,
        events: Sequence[ResourceActivityEvent] = (),
    ) -> Optional[ActivityContext]:
        """Evaluate this profile against a session (+ its events)."""
        if not self.enabled:
            return None
        matched = self._matches(session, events)
        if matched is None:
            return None
        return ActivityContext(
            approved=True,
            profile_id=self.profile_id,
            profile_version=self.version,
            justification=self.justification or self.activity,
            matched_constraints=matched,
        )


def match_profile(
    session: DestructiveActivitySession,
    profiles: Sequence[ApprovedActivityProfile],
    events: Sequence[ResourceActivityEvent] = (),
) -> Optional[ActivityContext]:
    """First matching enabled, non-expired profile for the session."""
    for profile in profiles:
        if not profile.enabled:
            continue
        context = profile.match(session, events)
        if context is not None:
            return context
    return None
