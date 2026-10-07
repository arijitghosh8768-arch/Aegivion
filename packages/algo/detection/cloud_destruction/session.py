"""Destructive-activity session builder.

Groups canonical :class:`ResourceActivityEvent` records into per-actor,
time-contiguous :class:`DestructiveActivitySession` objects. Grouping is
purely observational — no risk judgement happens here.

Splitting rules (configuration, not hard-coded):

- a gap > ``idle_timeout_minutes`` starts a new session;
- a session longer than ``max_duration_hours`` is force-split;
- optionally, a change of account/region also splits (``key_by_account``).

Events with the same millisecond timestamp and actor stay together. Events
missing an actor are grouped under a ``None`` key so their activity is still
countable — never attributed to someone else.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from algo.detection.cloud_destruction.config import SessionConfig
from algo.detection.cloud_destruction.exceptions import SessionBuildError
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    BusinessCriticality,
    DESTRUCTIVE_CATEGORIES,
    DestructiveActivitySession,
    ResourceActivityEvent,
)


def _is_destructive(event: ResourceActivityEvent) -> bool:
    return event.action_category in DESTRUCTIVE_CATEGORIES


class DestructiveSessionBuilder:
    """Builds :class:`DestructiveActivitySession` objects from canonical events."""

    def __init__(self, config: Optional[SessionConfig] = None) -> None:
        self._config = config or SessionConfig()

    def build_sessions(
        self, events: list[ResourceActivityEvent]
    ) -> list[DestructiveActivitySession]:
        """Group events into sessions. Input order does not matter."""
        if not isinstance(events, list):
            raise SessionBuildError("events must be a list of ResourceActivityEvent")

        # Bucket by actor (+ account/region when configured), then split by time.
        streams: dict[tuple, list[ResourceActivityEvent]] = defaultdict(list)
        for event in events:
            account = event.account_id if self._config.key_by_account else None
            region = event.region if self._config.key_by_account else None
            streams[(event.actor_id, account, region)].append(event)

        sessions: list[DestructiveActivitySession] = []
        for (actor_id, account, region), stream in streams.items():
            ordered = sorted(stream, key=lambda e: (e.timestamp, e.event_id))
            sessions.extend(self._split_stream(actor_id, account, region, ordered))
        return sessions

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _split_stream(
        self,
        actor_id: Optional[str],
        account: Optional[str],
        region: Optional[str],
        ordered: list[ResourceActivityEvent],
    ) -> list[DestructiveActivitySession]:
        idle_gap = timedelta(minutes=self._config.idle_timeout_minutes)
        max_span = timedelta(hours=self._config.max_duration_hours)

        chunks: list[list[ResourceActivityEvent]] = []
        current: list[ResourceActivityEvent] = []
        chunk_start: Optional[datetime] = None

        for event in ordered:
            if current:
                gap = event.timestamp - current[-1].timestamp
                span = event.timestamp - chunk_start  # type: ignore[operator]
                if gap > idle_gap or span > max_span:
                    chunks.append(current)
                    current = []
                    chunk_start = None
            if not current:
                chunk_start = event.timestamp
            current.append(event)
        if current:
            chunks.append(current)

        sessions: list[DestructiveActivitySession] = []
        for chunk in chunks:
            sessions.append(self._materialize(actor_id, account, region, chunk))
        return sessions

    def _materialize(
        self,
        actor_id: Optional[str],
        account: Optional[str],
        region: Optional[str],
        chunk: list[ResourceActivityEvent],
    ) -> DestructiveActivitySession:
        session = DestructiveActivitySession(
            session_id=str(uuid.uuid4()),
            actor_id=actor_id,
            provider=chunk[0].provider,
            account_id=account,
            start_time=chunk[0].timestamp,
            end_time=chunk[-1].timestamp,
            event_count=len(chunk),
            event_ids=[e.event_id for e in chunk],
        )

        modified: set[str] = set()
        deleted: set[str] = set()
        resource_types: set[str] = set()
        critical_hit = False

        for event in chunk:
            resource_types.add(event.resource_type.value)
            if event.business_criticality is BusinessCriticality.CRITICAL:
                critical_hit = True

            category = event.action_category
            resource_key = event.resource_arn or event.resource_id or event.object_key

            if category in (ActionCategory.MODIFY, ActionCategory.REWRITE):
                if resource_key:
                    modified.add(resource_key)
            elif category is ActionCategory.DELETE:
                if resource_key:
                    deleted.add(resource_key)
            elif category is ActionCategory.PROTECTION_CHANGE:
                pass
            elif category is ActionCategory.RESTORE:
                session.restore_count += 1

            if category in DESTRUCTIVE_CATEGORIES:
                session.destructive_event_count += 1

            if category is ActionCategory.VERSION_DELETE:
                session.version_deletions += 1
            if event.is_delete_marker:
                # Delete markers appear on plain DELETE (versioned buckets)
                # and on explicit version deletions alike.
                session.delete_marker_count += 1
            elif category is ActionCategory.SNAPSHOT_DELETE:
                session.snapshot_deletions += 1
            elif category is ActionCategory.BACKUP_DELETE:
                session.backup_deletions += 1
            elif category is ActionCategory.RECOVERY_POINT_DELETE:
                session.backup_deletions += 1
            elif category is ActionCategory.PROTECTION_CHANGE:
                session.protection_changes += 1
            elif category is ActionCategory.REWRITE:
                session.rewrite_count += 1

        session.modified_resources = sorted(m for m in modified if m not in deleted)
        session.deleted_resources = sorted(deleted)
        session.unique_resource_count = len(
            {e.resource_arn or e.resource_id or e.object_key for e in chunk if (e.resource_arn or e.resource_id or e.object_key)}
        )
        session.unique_resource_types = len(resource_types)
        session.resources_touched = sorted(
            {e.resource_arn or e.resource_id or e.object_key for e in chunk if (e.resource_arn or e.resource_id or e.object_key)}
        )
        session.critical_resource_touched = critical_hit
        session.risk_state = "analyzed"
        return session


__all__ = ["DestructiveSessionBuilder"]
