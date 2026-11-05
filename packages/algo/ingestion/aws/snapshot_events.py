"""Snapshot-event ingestion (EBS via EventBridge, RDS via EventBridge).

Snapshot *lifecycle* notifications arrive as EventBridge messages (EBS
``EC2 Snapshot Create``/``Copy``/``Delete``; RDS DB snapshot events).
Deletion calls also appear in CloudTrail and are handled by the CloudTrail
normalizer; this module covers the service-event stream, which carries
state that CloudTrail lacks.

Only resource-affecting detail types are normalized; anything else is
skipped as unsupported. Raw detail types and states are kept as evidence.
"""

from __future__ import annotations

from typing import Any, Optional

from algo.detection.cloud_destruction.config import NORMALIZER_VERSION
from algo.detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from algo.detection.cloud_destruction.normalizer import _parse_timestamp
from algo.detection.cloud_destruction.provenance import (
    AvailabilityTracker,
    DataProvenance,
    UnavailableReason,
)
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    OperationType,
    ResourceActivityEvent,
    ResourceType,
)

#: EventBridge ``detail-type`` values in scope for snapshot lifecycle.
_SNAPSHOT_DETAIL_TYPES = {
    "EC2 Snapshot Create",
    "EC2 Snapshot Copy",
    "EC2 Snapshot Delete",
    "RDS DB Snapshot Event",
}

#: RDS event IDs representing snapshot deletion / manual snapshot deletion.
_RDS_DELETION_EVENT_IDS = {"RDS-EVENT-0150", "RDS-EVENT-0058", "RDS-EVENT-0063"}


def normalize_snapshot_service_event(
    record: dict[str, Any],
    *,
    raw_event_reference: Optional[str] = None,
    raw_record_index: Optional[int] = None,
    is_replayed: bool = False,
    is_synthetic: bool = False,
    generator: Optional[str] = None,
) -> ResourceActivityEvent:
    """Normalize one EventBridge snapshot-lifecycle message.

    Raises :class:`UnsupportedEventError` for detail types out of scope and
    :class:`MalformedEventError` for structurally broken messages.
    """
    if not isinstance(record, dict):
        raise MalformedEventError("EventBridge record must be a dict", raw_event=record)

    detail_type = record.get("detail-type")
    if not isinstance(detail_type, str) or not detail_type.strip():
        raise MalformedEventError(
            "EventBridge record missing detail-type",
            missing_fields=["detail-type"],
            raw_event=record,
        )
    if detail_type not in _SNAPSHOT_DETAIL_TYPES:
        raise UnsupportedEventError(f"out-of-scope snapshot detail-type {detail_type!r}")

    event_id = record.get("id")
    if not isinstance(event_id, str) or not event_id.strip():
        raise MalformedEventError(
            "EventBridge record missing id", missing_fields=["id"], raw_event=record
        )

    detail = record.get("detail")
    if not isinstance(detail, dict):
        raise MalformedEventError(
            "EventBridge record missing detail object",
            missing_fields=["detail"],
            raw_event=record,
        )

    tracker = AvailabilityTracker()
    tracker.available("event_id")
    tracker.available("timestamp")

    timestamp = _parse_timestamp(record.get("time"))
    account_id = record.get("account")
    if isinstance(account_id, str) and account_id.strip():
        tracker.available("account_id")
    else:
        account_id = None
        tracker.unavailable("account_id", UnavailableReason.NOT_IN_SOURCE)
    region = record.get("region")
    if isinstance(region, str) and region.strip():
        tracker.available("region")
    else:
        region = None
        tracker.unavailable("region", UnavailableReason.NOT_IN_SOURCE)

    source = detail.get("source")
    source_str = str(source) if source else ("ec2" if detail_type.startswith("EC2") else "rds")
    snapshot_id: Optional[str] = None
    for key in ("snapshot_id", "SnapshotId", "source", "SourceId"):
        value = detail.get(key)
        if isinstance(value, str) and value.startswith("snap-"):
            snapshot_id = value
            break
    if snapshot_id:
        tracker.available("snapshot_id")
    else:
        tracker.unavailable("snapshot_id", UnavailableReason.NOT_IN_SOURCE)

    state = detail.get("state") or detail.get("State") or detail.get("Message")
    if isinstance(state, str) and state.strip():
        tracker.available("operation_type", derived=True)
    else:
        state = None
        tracker.unavailable("operation_type", UnavailableReason.NOT_IN_SOURCE)

    event_id_rds = str(detail.get("EventID") or detail.get("eventID") or "")
    is_deletion = detail_type == "EC2 Snapshot Delete" or (
        source_str == "rds" and event_id_rds in _RDS_DELETION_EVENT_IDS
    )

    action_category = ActionCategory.SNAPSHOT_DELETE if is_deletion else ActionCategory.CREATE
    operation = OperationType.SINGLE
    raw_action = f"{source_str}:{detail_type}" + (f":{event_id_rds}" if event_id_rds else "")

    resource_type = (
        ResourceType.RDS_SNAPSHOT if source_str == "rds" else ResourceType.EBS_SNAPSHOT
    )

    for field_name in (
        "object_key",
        "version_id",
        "object_count",
        "bytes_changed",
        "source_ip",
        "user_agent",
    ):
        tracker.unavailable(field_name, UnavailableReason.FIELD_NOT_APPLICABLE)
    tracker.unavailable("recovery_point_id", UnavailableReason.FIELD_NOT_APPLICABLE)
    tracker.unavailable("backup_vault_name", UnavailableReason.FIELD_NOT_APPLICABLE)
    for field_name in (
        "actor_id",
        "actor_type",
        "session_id",
        "resource_id",
        "resource_arn",
    ):
        if field_name == "resource_id" and snapshot_id:
            tracker.available("resource_id")
            continue
        tracker.unavailable(field_name, UnavailableReason.NOT_IN_SOURCE)
    for field_name in (
        "business_criticality",
        "sensitivity_level",
        "versioning_enabled",
        "object_lock_enabled",
        "backup_enabled",
        "snapshot_protection_enabled",
        "retention_period",
    ):
        tracker.unavailable(field_name, UnavailableReason.ENRICHMENT_MISSING)

    provenance = DataProvenance(
        source_type="eventbridge",
        ingestion_pipeline="aws.snapshot_events",
        raw_record_index=raw_record_index,
        raw_reference=raw_event_reference,
        is_replayed=is_replayed,
        is_synthetic=is_synthetic,
        generator=generator,
        normalizer_version=NORMALIZER_VERSION,
    )

    return ResourceActivityEvent(
        event_id=f"eb-{event_id.strip()}",
        timestamp=timestamp,
        account_id=account_id,
        region=region,
        resource_id=snapshot_id,
        resource_type=resource_type,
        resource_arn=(
            f"arn:aws:ec2:{region or ''}:{account_id or ''}:snapshot/{snapshot_id}"
            if snapshot_id and source_str == "ec2"
            else None
        ),
        action=action_category.value,
        action_category=action_category,
        operation_type=operation,
        raw_action=raw_action,
        snapshot_id=snapshot_id,
        request_parameters={"state": state} if state else None,
        raw_event_reference=raw_event_reference,
        feature_availability=tracker.to_tuple(),
        data_provenance=provenance,
    )


class SnapshotEventIngestor:
    """Batch ingestor for EventBridge snapshot-lifecycle messages."""

    def __init__(self, *, strict: bool = True) -> None:
        self._strict = strict

    def ingest_batch(self, records: list[dict[str, Any]]) -> dict[str, list[Any]]:
        """Return ``{"events": [...], "skipped": [...], "quarantined": [...]}``."""
        events: list[ResourceActivityEvent] = []
        skipped: list[dict[str, Any]] = []
        quarantined: list[dict[str, Any]] = []
        for index, record in enumerate(records):
            try:
                events.append(
                    normalize_snapshot_service_event(
                        record,
                        raw_event_reference=f"eventbridge://snapshots/{record.get('id', index)}",
                        raw_record_index=index,
                    )
                )
            except UnsupportedEventError as exc:
                skipped.append({"index": index, "reason": str(exc)})
            except MalformedEventError as exc:
                if self._strict:
                    raise
                quarantined.append({"index": index, "error": str(exc), "record": record})
        return {"events": events, "skipped": skipped, "quarantined": quarantined}


__all__ = ["SnapshotEventIngestor", "normalize_snapshot_service_event"]
