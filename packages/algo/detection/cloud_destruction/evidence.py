"""Per-session evidence counters shared by the Part 2 analyzers.

A thin, deterministic aggregation layer over a
:class:`~detection.cloud_destruction.schemas.DestructiveActivitySession`
plus the session's canonical events. Every analyzer reads the *same*
counters so a feature can always be audited back to the raw events that
produced it. Nothing here scores or judges — these are counts, spans and
sets.

Two evidence modes:

- **event mode** (``events`` provided): every counter is computed from the
  canonical events (authoritative and most detailed).
- **aggregate mode** (no events): only counters Part 1 sessions carry are
  available; the rest stay ``None`` ("unknown"), never zero.

``EventDetailMissingError`` is *not* raised for missing detail — absence is
recorded as ``None`` and analyzers report the corresponding features
unavailable with a machine-readable reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    BusinessCriticality,
    DESTRUCTIVE_CATEGORIES,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

#: Categories that consume or destroy recovery state (deletion family).
DELETION_FAMILY: frozenset[ActionCategory] = frozenset(
    {
        ActionCategory.DELETE,
        ActionCategory.VERSION_DELETE,
        ActionCategory.SNAPSHOT_DELETE,
        ActionCategory.BACKUP_DELETE,
        ActionCategory.RECOVERY_POINT_DELETE,
    }
)

_CRITICALITY_ORDER: dict[str, int] = {
    "unclassified": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class SessionEvidence:
    """Raw per-session counters used by every Part 2 analyzer.

    ``None`` means "not derivable from the provided evidence" — it must
    never be interpreted as zero.
    """

    session_id: str
    actor_id: str | None

    # provided inputs
    events: tuple[ResourceActivityEvent, ...] = ()
    has_event_detail: bool = False

    # core counts
    event_count: int = 0
    destructive_event_count: int = 0

    write_events: int | None = None
    read_events: int | None = None
    create_events: int | None = None
    modify_events: int | None = None
    rewrite_events: int | None = None
    delete_events: int | None = None
    """Plain (non-version, non-snapshot/backup) deletions."""
    delete_family_events: int | None = None
    """All deletion-family events (plain + version + snapshot + backup + RP)."""
    restore_events: int | None = None

    version_delete_events: int | None = None
    delete_marker_events: int | None = None
    snapshot_delete_events: int | None = None
    ebs_snapshot_delete_events: int | None = None
    rds_snapshot_delete_events: int | None = None
    backup_delete_events: int | None = None
    """``backup:DeleteBackupVault``-class events."""
    recovery_point_delete_events: int | None = None
    protection_change_events: int | None = None
    policy_change_events: int | None = None
    share_change_events: int | None = None

    # scope
    unique_resource_count: int = 0
    unique_resource_types: int = 0
    unique_snapshots: int | None = None
    unique_recovery_points: int | None = None
    unique_vaults: int | None = None

    max_object_count: int | None = None
    total_bytes_changed: int | None = None

    # criticality
    criticality_rank: int = -1
    has_criticality: bool = False
    critical_resource_touched: bool = False

    # cross-event detail (event mode only)
    rewritten_keys: frozenset[str] = frozenset()
    read_then_rewritten_keys: frozenset[str] = frozenset()
    rewritten_then_deleted_keys: frozenset[str] = frozenset()
    version_deletes_per_key: dict[str, int] = field(default_factory=dict)
    protected_snapshot_deletions: int = 0
    protected_backup_deletions: int = 0

    # timing (event mode when available; aggregate start/end otherwise)
    start_time: datetime | None = None
    end_time: datetime | None = None
    event_times: tuple[datetime, ...] = ()
    destructive_event_times: tuple[datetime, ...] = ()
    first_destructive_index: int | None = None
    resources_before_first_destructive: frozenset[str] = frozenset()
    resources_after_first_destructive: frozenset[str] = frozenset()

    @property
    def duration_seconds(self) -> float:
        if self.start_time is None or self.end_time is None:
            return 0.0
        return max(0.0, (self.end_time - self.start_time).total_seconds())

    @property
    def delete_ratio(self) -> float | None:
        """Deletion-family share of all events (None without event detail)."""
        if not self.has_event_detail or self.event_count == 0:
            return None
        return (
            (self.delete_events or 0)
            + (self.version_delete_events or 0)
            + (self.snapshot_delete_events or 0)
            + (self.backup_delete_events or 0)
            + (self.recovery_point_delete_events or 0)
        ) / self.event_count

    @property
    def recovery_impairing_events(self) -> int:
        """Snapshot + backup-vault + recovery-point deletion events.

        In aggregate mode the recovery-point split is unknown (Part 1 folds
        it into ``backup_deletions``), so only the known counters count.
        """
        return (self.snapshot_delete_events or 0) + (self.backup_delete_events or 0) + (
            self.recovery_point_delete_events or 0
        )

    @property
    def max_criticality(self) -> BusinessCriticality | None:
        if not self.has_criticality or self.criticality_rank < 0:
            return None
        for candidate in BusinessCriticality:
            if _CRITICALITY_ORDER.get(candidate.value, -1) == self.criticality_rank:
                return candidate
        return None


def collect_evidence(
    session: DestructiveActivitySession,
    events: list[ResourceActivityEvent] | None = None,
) -> SessionEvidence:
    """Aggregate one session (+ its events when known) into evidence counters."""
    evidence = SessionEvidence(
        session_id=session.session_id,
        actor_id=session.actor_id,
        events=tuple(events or ()),
        has_event_detail=events is not None and len(events) > 0,
        event_count=session.event_count,
        destructive_event_count=session.destructive_event_count,
        rewrite_events=session.rewrite_count,
        version_delete_events=session.version_deletions,
        delete_marker_events=session.delete_marker_count,
        snapshot_delete_events=session.snapshot_deletions,
        backup_delete_events=session.backup_deletions,
        protection_change_events=session.protection_changes,
        restore_events=session.restore_count,
        unique_resource_count=session.unique_resource_count,
        unique_resource_types=session.unique_resource_types,
        critical_resource_touched=session.critical_resource_touched,
        start_time=session.start_time,
        end_time=session.end_time,
    )
    # Session aggregates fold recovery-point deletions into backup_deletions
    # and do not count plain deletes; without event detail both are unknown,
    # not zero (deletion analyzers derive a documented lower bound).
    evidence.recovery_point_delete_events = None
    evidence.delete_family_events = None

    if not events:
        return evidence

    # ---- event mode: authoritative, detailed counters ---------------------
    resource_keys: set[str] = set()
    resource_types: set[str] = set()
    snapshot_ids: set[str] = set()
    recovery_point_ids: set[str] = set()
    vault_names: set[str] = set()
    read_keys: set[str] = set()
    rewritten_keys: set[str] = set()
    deleted_keys: set[str] = set()
    version_delete_counts: dict[str, int] = {}
    times: list[datetime] = []
    destructive_times: list[datetime] = []
    first_destructive_index: int | None = None
    resources_before: set[str] = set()
    resources_after: set[str] = set()

    counts = {
        "write": 0,
        "read": 0,
        "create": 0,
        "modify": 0,
        "rewrite": 0,
        "delete": 0,
        "version_delete": 0,
        "delete_marker": 0,
        "snapshot_delete": 0,
        "ebs_snapshot_delete": 0,
        "rds_snapshot_delete": 0,
        "backup_delete": 0,
        "recovery_point_delete": 0,
        "protection_change": 0,
        "policy_change": 0,
        "share_change": 0,
        "restore": 0,
    }
    protected_snapshots = 0
    protected_backups = 0
    max_object_count: int | None = None
    total_bytes: int | None = None
    criticality_rank = -1
    has_criticality = False

    for index, event in enumerate(events):
        times.append(event.timestamp)
        # Snapshot the pre-existing scope BEFORE this event's own target is
        # added: "resources touched before the first destructive event" must
        # not include the target the destructive event itself hits.
        if first_destructive_index is None and event.is_destructive:
            first_destructive_index = index
            resources_before = set(resource_keys)
        key = event.resource_arn or event.resource_id or event.object_key
        if key:
            resource_keys.add(key)
        resource_types.add(event.resource_type.value)

        category = event.action_category
        if category is ActionCategory.READ:
            counts["read"] += 1
            object_key = event.object_key or key
            if object_key:
                read_keys.add(object_key)
        elif category is ActionCategory.CREATE:
            counts["create"] += 1
            counts["write"] += 1
        elif category is ActionCategory.MODIFY:
            counts["modify"] += 1
        elif category is ActionCategory.REWRITE:
            counts["rewrite"] += 1
            rewrite_key = event.object_key or key
            if rewrite_key:
                rewritten_keys.add(rewrite_key)
        elif category is ActionCategory.DELETE:
            counts["delete"] += 1
            delete_key = event.object_key or key
            if delete_key:
                deleted_keys.add(delete_key)
        elif category is ActionCategory.VERSION_DELETE:
            counts["version_delete"] += 1
            version_key = event.object_key or key
            if version_key:
                version_delete_counts[version_key] = (
                    version_delete_counts.get(version_key, 0) + 1
                )
        elif category is ActionCategory.SNAPSHOT_DELETE:
            counts["snapshot_delete"] += 1
            snapshot_id = event.snapshot_id or event.resource_id
            if snapshot_id:
                snapshot_ids.add(snapshot_id)
            if event.resource_type.value == "rds_snapshot":
                counts["rds_snapshot_delete"] += 1
            else:
                counts["ebs_snapshot_delete"] += 1
        elif category is ActionCategory.BACKUP_DELETE:
            counts["backup_delete"] += 1
            if event.backup_vault_name:
                vault_names.add(event.backup_vault_name)
        elif category is ActionCategory.RECOVERY_POINT_DELETE:
            counts["recovery_point_delete"] += 1
            recovery_point_id = event.recovery_point_id or event.resource_id
            if recovery_point_id:
                recovery_point_ids.add(recovery_point_id)
            if event.backup_vault_name:
                vault_names.add(event.backup_vault_name)
        elif category is ActionCategory.PROTECTION_CHANGE:
            counts["protection_change"] += 1
        elif category is ActionCategory.POLICY_CHANGE:
            counts["policy_change"] += 1
        elif category is ActionCategory.SHARE_CHANGE:
            counts["share_change"] += 1
        elif category is ActionCategory.RESTORE:
            counts["restore"] += 1

        if event.is_delete_marker:
            counts["delete_marker"] += 1

        if event.business_criticality is not None:
            has_criticality = True
            rank = _CRITICALITY_ORDER.get(event.business_criticality.value, 0)
            criticality_rank = max(criticality_rank, rank)

        if event.object_count is not None:
            max_object_count = (
                event.object_count
                if max_object_count is None
                else max(max_object_count, event.object_count)
            )
        if event.bytes_changed is not None:
            total_bytes = (total_bytes or 0) + event.bytes_changed

        # protection state observed at event time (enriched, never guessed)
        if category is ActionCategory.SNAPSHOT_DELETE and event.snapshot_protection_enabled:
            protected_snapshots += 1
        if category in (ActionCategory.BACKUP_DELETE, ActionCategory.RECOVERY_POINT_DELETE) and (
            event.backup_enabled or event.object_lock_enabled or event.versioning_enabled
        ):
            protected_backups += 1

        if event.is_destructive:
            destructive_times.append(event.timestamp)
        if first_destructive_index is not None and key:
            resources_after.add(key)

    evidence.has_event_detail = True
    evidence.write_events = counts["write"]
    evidence.read_events = counts["read"]
    evidence.create_events = counts["create"]
    evidence.modify_events = counts["modify"]
    evidence.rewrite_events = counts["rewrite"]
    evidence.delete_events = counts["delete"]
    evidence.version_delete_events = counts["version_delete"]
    evidence.delete_marker_events = counts["delete_marker"]
    evidence.snapshot_delete_events = counts["snapshot_delete"]
    evidence.ebs_snapshot_delete_events = counts["ebs_snapshot_delete"]
    evidence.rds_snapshot_delete_events = counts["rds_snapshot_delete"]
    evidence.backup_delete_events = counts["backup_delete"]
    evidence.recovery_point_delete_events = counts["recovery_point_delete"]
    evidence.protection_change_events = counts["protection_change"]
    evidence.policy_change_events = counts["policy_change"]
    evidence.share_change_events = counts["share_change"]
    evidence.restore_events = counts["restore"]
    evidence.delete_family_events = (
        counts["delete"]
        + counts["version_delete"]
        + counts["snapshot_delete"]
        + counts["backup_delete"]
        + counts["recovery_point_delete"]
    )
    evidence.unique_snapshots = len(snapshot_ids)
    evidence.unique_recovery_points = len(recovery_point_ids)
    evidence.unique_vaults = len(vault_names)
    evidence.max_object_count = max_object_count
    evidence.total_bytes_changed = total_bytes
    evidence.criticality_rank = criticality_rank
    evidence.has_criticality = has_criticality
    evidence.rewritten_keys = frozenset(rewritten_keys)
    evidence.read_then_rewritten_keys = frozenset(read_keys & rewritten_keys)
    evidence.rewritten_then_deleted_keys = frozenset(rewritten_keys & deleted_keys)
    evidence.version_deletes_per_key = version_delete_counts
    evidence.protected_snapshot_deletions = protected_snapshots
    evidence.protected_backup_deletions = protected_backups
    evidence.event_times = tuple(times)
    evidence.destructive_event_times = tuple(destructive_times)
    evidence.first_destructive_index = first_destructive_index
    evidence.resources_before_first_destructive = frozenset(resources_before)
    evidence.resources_after_first_destructive = frozenset(resources_after)
    if times:
        evidence.start_time = times[0]
        evidence.end_time = times[-1]
    if resource_types:
        evidence.unique_resource_types = len(resource_types)
    if resource_keys:
        evidence.unique_resource_count = len(resource_keys)
    return evidence


__all__ = ["DELETION_FAMILY", "SessionEvidence", "collect_evidence"]
