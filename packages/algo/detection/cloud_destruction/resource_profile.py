"""Resource profile builder.

Part 1 records **descriptive history** per resource: how much write/modify/
delete/rewrite activity was observed, which actors performed it, and when.
Deriving baseline *statistics* and judging deviation is Part 2 work
(:mod:`detection.cloud_destruction.baseline`). Nothing here flags or scores.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from detection.cloud_destruction.config import ProfileConfig
from detection.cloud_destruction.protection import ProtectionCatalog
from detection.cloud_destruction.schemas import (
    ActionCategory,
    BusinessCriticality,
    CloudProvider,
    ResourceActivityEvent,
    ResourceProtectionProfile,
    ResourceType,
    ensure_utc,
)


class ResourceProfileBuilder:
    """Builds :class:`ResourceProtectionProfile`s from canonical event history."""

    def __init__(
        self,
        catalog: Optional[ProtectionCatalog] = None,
        config: Optional[ProfileConfig] = None,
    ) -> None:
        self._catalog = catalog
        self._config = config or ProfileConfig()

    def build_profiles(
        self, events: list[ResourceActivityEvent]
    ) -> dict[str, ResourceProtectionProfile]:
        """Aggregate a historical event list into per-resource profiles."""
        grouped: dict[str, list[ResourceActivityEvent]] = defaultdict(list)
        for event in events:
            if not event.resource_id:
                continue
            grouped[event.resource_id].append(event)

        profiles: dict[str, ResourceProtectionProfile] = {}
        for resource_id, resource_events in grouped.items():
            profiles[resource_id] = self._build(resource_id, resource_events)
        return profiles

    def _build(
        self, resource_id: str, events: list[ResourceActivityEvent]
    ) -> ResourceProtectionProfile:
        events = sorted(events, key=lambda e: e.timestamp)
        first = events[0]
        profile = ResourceProtectionProfile(resource_id=resource_id)

        if self._catalog is not None:
            state = self._catalog.enrich(resource_id, None)
            if state.is_known:
                profile.business_criticality = state.business_criticality
                profile.versioning_enabled = state.versioning_enabled
                profile.object_lock_enabled = state.object_lock_enabled
                profile.backup_enabled = state.backup_enabled
                profile.snapshot_protection_enabled = state.snapshot_protection_enabled
                if isinstance(state.details.get("recovery_point_available"), bool):
                    profile.recovery_point_available = state.details["recovery_point_available"]
                if state.retention_period is not None:
                    profile.retention_configuration = {"retention_days": state.retention_period}

        profile.resource_type = first.resource_type
        profile.resource_arn = first.resource_arn
        profile.business_criticality = profile.business_criticality or first.business_criticality

        counters: dict[str, int] = defaultdict(int)
        actors: set[str] = set()
        windows: dict[str, int] = defaultdict(int)

        for event in events:
            category = event.action_category
            if category in (ActionCategory.CREATE, ActionCategory.READ):
                counters["write"] += 1
            if category in (ActionCategory.MODIFY, ActionCategory.REWRITE):
                counters["modify"] += 1
            if category in (
                ActionCategory.DELETE,
                ActionCategory.VERSION_DELETE,
                ActionCategory.SNAPSHOT_DELETE,
                ActionCategory.BACKUP_DELETE,
                ActionCategory.RECOVERY_POINT_DELETE,
            ):
                counters["delete"] += 1
            if category is ActionCategory.REWRITE:
                counters["rewrite"] += 1
            if event.actor_id:
                actors.add(event.actor_id)

            hour = event.timestamp.astimezone(event.timestamp.tzinfo or None).hour
            bucket = f"{hour:02d}-{(hour + 1) % 24:02d}"
            windows[bucket] += 1

        profile.observed_write_events = counters["write"]
        profile.observed_modify_events = counters["modify"]
        profile.observed_delete_events = counters["delete"]
        profile.observed_rewrite_events = counters["rewrite"]
        profile.history_event_count = len(events)
        profile.observation_start = first.timestamp
        profile.observation_end = events[-1].timestamp
        profile.normal_actor_set = tuple(sorted(actors))

        span_days = max(
            (profile.observation_end - profile.observation_start).total_seconds() / 86400.0,
            1.0,
        )
        profile.normal_write_rate = counters["write"] / span_days
        profile.normal_modify_rate = counters["modify"] / span_days
        profile.normal_delete_rate = counters["delete"] / span_days
        profile.normal_rewrite_rate = counters["rewrite"] / span_days
        profile.normal_change_windows = tuple(
            f"{bucket}:{count}" for bucket, count in sorted(windows.items())
        )
        return profile


__all__ = ["ResourceProfileBuilder"]
