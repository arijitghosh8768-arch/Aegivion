"""AWS Backup service-event ingestion (EventBridge-delivered ``aws.backup``).

Backup, copy and restore jobs are reported as EventBridge messages
(``detail-type`` like ``Backup Job State Change``). Recovery-point deletion
also arrives through CloudTrail, but the EventBridge stream carries job
lifecycle state (``EXPIRED``, ``DELETE_COMPLETED``) that CloudTrail lacks, so
it is a first-class source for recovery-protection degradation.

Only *resource-affecting* detail types are normalized; anything else is
skipped as unsupported. State values are kept verbatim as evidence.
"""

from __future__ import annotations

from typing import Any, Optional

from detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from detection.cloud_destruction.normalizer import (
    _parse_timestamp,
    _resource_id_from_arn,
)
from detection.cloud_destruction.protection import ProtectionCatalog
from detection.cloud_destruction.provenance import (
    AvailabilityTracker,
    DataProvenance,
    UnavailableReason,
)
from detection.cloud_destruction.config import NORMALIZER_VERSION
from detection.cloud_destruction.schemas import (
    ActionCategory,
    OperationType,
    ResourceActivityEvent,
    ResourceType,
)

#: EventBridge ``detail-type`` values in scope, mapped to canonical categories.
_DETAIL_TYPE_MAP: dict[str, ActionCategory] = {
    "Backup Job State Change": ActionCategory.CREATE,
    "Copy Job State Change": ActionCategory.CREATE,
    "Restore Job State Change": ActionCategory.RESTORE,
}

#: Recovery-point terminal states that represent destruction of a recovery
#: point (as reported by the service, kept as evidence in ``raw_action``).
_DESTRUCTIVE_JOB_STATES = {"EXPIRED", "DELETE_COMPLETED", "ABORTED"}

_BACKUP_VAULT_ARN_PREFIX = "arn:aws:backup"


def normalize_backup_service_event(
    record: dict[str, Any],
    catalog: Optional[ProtectionCatalog] = None,
    *,
    raw_event_reference: Optional[str] = None,
    raw_record_index: Optional[int] = None,
    is_replayed: bool = False,
    is_synthetic: bool = False,
    generator: Optional[str] = None,
) -> ResourceActivityEvent:
    """Normalize one EventBridge ``aws.backup`` message.

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
    category = _DETAIL_TYPE_MAP.get(detail_type)
    if category is None:
        raise UnsupportedEventError(f"out-of-scope backup detail-type {detail_type!r}")

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
    tracker.available("action_category")

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

    recovery_point_ref = detail.get("recoveryPointArn") or detail.get("recoveryPointId")
    recovery_point_id: Optional[str] = None
    recovery_point_arn: Optional[str] = None
    if isinstance(recovery_point_ref, str) and recovery_point_ref.strip():
        if recovery_point_ref.startswith("arn:"):
            recovery_point_arn = recovery_point_ref
            recovery_point_id = _resource_id_from_arn(recovery_point_ref)
        else:
            recovery_point_id = recovery_point_ref
    if recovery_point_id:
        tracker.available("recovery_point_id")
    else:
        tracker.unavailable("recovery_point_id", UnavailableReason.NOT_IN_SOURCE)

    vault_arn = detail.get("backupVaultArn")
    vault_name: Optional[str] = None
    if isinstance(vault_arn, str) and vault_arn.startswith(_BACKUP_VAULT_ARN_PREFIX):
        vault_name = vault_arn.rsplit(":", 1)[-1].split("/", 1)[-1] or None
    if vault_name:
        tracker.available("backup_vault_name")
    else:
        tracker.unavailable("backup_vault_name", UnavailableReason.NOT_IN_SOURCE)

    state = detail.get("state")
    if isinstance(state, str) and state.strip():
        tracker.available("operation_type", derived=True)
    else:
        state = None
        tracker.unavailable("operation_type", UnavailableReason.NOT_IN_SOURCE)

    resource_id: Optional[str] = recovery_point_id
    resource_type = (
        ResourceType.RECOVERY_POINT
        if category in {ActionCategory.RECOVERY_POINT_DELETE, ActionCategory.DELETE}
        else ResourceType.BACKUP_VAULT
    )

    # Deletion/expiry is expressed as a terminal job state on this stream.
    action_category = category
    operation = OperationType.SINGLE
    raw_action = f"backup:{detail_type}"
    if state and state.upper() in _DESTRUCTIVE_JOB_STATES and detail_type == "Backup Job State Change":
        action_category = ActionCategory.RECOVERY_POINT_DELETE
        raw_action = f"backup:{detail_type}:{state.upper()}"

    if action_category is ActionCategory.RECOVERY_POINT_DELETE:
        operation = OperationType.RECOVERY_IMPAIRING

    for field_name in (
        "object_key",
        "version_id",
        "snapshot_id",
        "object_count",
        "bytes_changed",
        "source_ip",
        "user_agent",
    ):
        tracker.unavailable(field_name, UnavailableReason.FIELD_NOT_APPLICABLE)
    for field_name in (
        "actor_id",
        "actor_type",
        "session_id",
        "resource_id",
        "resource_arn",
    ):
        if field_name == "resource_id" and resource_id:
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
        ingestion_pipeline="aws.backup_events",
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
        resource_id=resource_id,
        resource_type=resource_type,
        resource_arn=recovery_point_arn,
        action=action_category.value,
        action_category=action_category,
        operation_type=operation,
        raw_action=raw_action,
        recovery_point_id=recovery_point_id,
        backup_vault_name=vault_name,
        request_parameters={"state": state} if state else None,
        raw_event_reference=raw_event_reference,
        feature_availability=tracker.to_tuple(),
        data_provenance=provenance,
    )


class BackupEventIngestor:
    """Batch ingestor for EventBridge ``aws.backup`` messages."""

    def __init__(self, catalog: Optional[ProtectionCatalog] = None, *, strict: bool = True) -> None:
        self._catalog = catalog
        self._strict = strict

    def ingest_batch(self, records: list[dict[str, Any]]) -> dict[str, list[Any]]:
        """Return ``{"events": [...], "skipped": [...], "quarantined": [...]}``."""
        events: list[ResourceActivityEvent] = []
        skipped: list[dict[str, Any]] = []
        quarantined: list[dict[str, Any]] = []
        for index, record in enumerate(records):
            try:
                events.append(
                    normalize_backup_service_event(
                        record,
                        self._catalog,
                        raw_event_reference=f"eventbridge://backup/{record.get('id', index)}",
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


__all__ = ["BackupEventIngestor", "normalize_backup_service_event"]
