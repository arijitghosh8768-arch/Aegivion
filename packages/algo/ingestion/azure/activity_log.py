"""Azure Activity Log -> canonical events ingestion (Part 5).

Normalizes Azure Monitor *Activity Log* records (the management
plane audit trail) into canonical :class:`ResourceActivityEvent`
records. Mirrors the AWS CloudTrail ingestor's contract:

- ``normalized``  — became a canonical event
- ``skipped``     — valid but out of scope (other categories,
  unmapped operations)
- ``quarantined`` — malformed; unusable as evidence

Design rules (inherited from the algorithm core):

1. **Nothing is invented.** Absent fields stay ``None`` with an
   availability record explaining why. Protection state comes only
   from a :class:`~detection.cloud_destruction.protection.ProtectionCatalog`
   — never from the operation name.
2. **Raw actions are evidence.** ``raw_action`` keeps the full
   ``Microsoft.*`` operation name next to the canonical category.
3. **Attempts are evidence.** A failed operation (``resultType``
   != ``Succeeded``) is still normalized — attempted destruction
   is detectable activity — and the failure is recorded as a
   provenance note.
4. **Azure types are not canonical types.** ``resource_type``
   stays ``UNKNOWN`` unless the evidence supports a canonical
   mapping; the Azure resource id is preserved verbatim as
   ``resource_arn``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from algo.detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from algo.detection.cloud_destruction.provenance import (
    AvailabilityTracker,
    DataProvenance,
    UnavailableReason,
)
from algo.detection.cloud_destruction.protection import ProtectionCatalog
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    ActorType,
    BusinessCriticality,
    CloudProvider,
    OperationType,
    ResourceActivityEvent,
    ResourceType,
    SensitivityLevel,
)

#: Bumped when the Azure operation mapping changes.
AZURE_NORMALIZER_VERSION = "1.0.0"

#: Activity Log categories this detector consumes.
_IN_SCOPE_CATEGORIES = frozenset({"Administrative", "Security", "Policy"})

#: Azure operation name -> (canonical category, operation nuance).
_OPERATION_MAP: dict[str, tuple[ActionCategory, OperationType]] = {
    # --- Storage accounts -------------------------------------------------
    "Microsoft.Storage/storageAccounts/delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "Microsoft.Storage/storageAccounts/write": (ActionCategory.MODIFY, OperationType.SINGLE),
    "Microsoft.Storage/storageAccounts/regenerateKey": (ActionCategory.POLICY_CHANGE, OperationType.SINGLE),
    "Microsoft.Storage/storageAccounts/restoreBlobRanges": (ActionCategory.RESTORE, OperationType.BATCH),
    # --- Blob / container data plane (management-plane ops) ---------------
    "Microsoft.Storage/storageAccounts/blobServices/containers/delete": (
        ActionCategory.DELETE,
        OperationType.SINGLE,
    ),
    "Microsoft.Storage/storageAccounts/blobServices/containers/undelete": (
        ActionCategory.RESTORE,
        OperationType.SINGLE,
    ),
    "Microsoft.Storage/storageAccounts/blobServices/containers/write": (
        ActionCategory.MODIFY,
        OperationType.SINGLE,
    ),
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete": (
        ActionCategory.DELETE,
        OperationType.SINGLE,
    ),
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/undelete": (
        ActionCategory.RESTORE,
        OperationType.SINGLE,
    ),
    # --- Key Vault (purge is irreversible -> recovery-impairing) ----------
    "Microsoft.KeyVault/vaults/delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "Microsoft.KeyVault/vaults/purge": (
        ActionCategory.RECOVERY_POINT_DELETE,
        OperationType.RECOVERY_IMPAIRING,
    ),
    "Microsoft.KeyVault/vaults/recover": (ActionCategory.RESTORE, OperationType.SINGLE),
    # --- Compute ------------------------------------------------------------
    "Microsoft.Compute/disks/delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "Microsoft.Compute/snapshots/delete": (ActionCategory.SNAPSHOT_DELETE, OperationType.SINGLE),
    "Microsoft.Compute/virtualMachines/delete": (ActionCategory.DELETE, OperationType.SINGLE),
    # --- Data services -------------------------------------------------------
    "Microsoft.DocumentDB/databaseAccounts/delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "Microsoft.Sql/servers/databases/delete": (ActionCategory.DELETE, OperationType.SINGLE),
    # --- Azure Backup (Recovery Services) ------------------------------------
    "Microsoft.RecoveryServices/vaults/delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "Microsoft.RecoveryServices/vaults/backupFabrics/protectionFabrics/protectionContainers/protectedItems/delete": (
        ActionCategory.BACKUP_DELETE,
        OperationType.SINGLE,
    ),
    "Microsoft.RecoveryServices/vaults/backupFabrics/protectionFabrics/protectionContainers/protectedItems/recoveryPoints/delete": (
        ActionCategory.RECOVERY_POINT_DELETE,
        OperationType.SINGLE,
    ),
    # --- Authorization (access policy) ----------------------------------------
    "Microsoft.Authorization/roleAssignments/write": (ActionCategory.POLICY_CHANGE, OperationType.SINGLE),
    "Microsoft.Authorization/roleAssignments/delete": (ActionCategory.POLICY_CHANGE, OperationType.SINGLE),
    "Microsoft.Authorization/roleDefinitions/write": (ActionCategory.POLICY_CHANGE, OperationType.SINGLE),
    "Microsoft.Authorization/roleDefinitions/delete": (ActionCategory.POLICY_CHANGE, OperationType.SINGLE),
}

#: Protection-state fields the normalizer never guesses.
_PROTECTION_FIELDS = (
    "business_criticality",
    "sensitivity_level",
    "versioning_enabled",
    "object_lock_enabled",
    "backup_enabled",
    "snapshot_protection_enabled",
    "retention_period",
)

# Azure timestamps: ISO-8601 with an optional 1-7 digit fraction and
# ``Z`` / offset zone designator, e.g. ``2024-01-02T03:04:05.1234567Z``.
_AZURE_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)


def _parse_timestamp(raw: Any) -> datetime:
    """Parse an Azure Activity Log ``time`` value into aware UTC."""
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not isinstance(raw, str):
        raise MalformedEventError(
            "Azure 'time' must be an ISO-8601 string",
            provider="azure",
            missing_fields=["time"],
        )
    match = _AZURE_TS_RE.match(raw.strip())
    if match is None:
        raise MalformedEventError(
            f"unparsable Azure timestamp {raw!r}",
            provider="azure",
            missing_fields=["time"],
        )
    base, fraction, zone = match.groups()
    # Python's fromisoformat accepts at most 6 fractional digits.
    fraction = fraction[:7] if fraction else ""
    zone = "+00:00" if zone in (None, "Z") else zone.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(f"{base}{fraction}{zone}")
    except ValueError as exc:
        raise MalformedEventError(
            f"unparsable Azure timestamp {raw!r}",
            provider="azure",
            missing_fields=["time"],
            cause=exc,
        ) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _operation_name(record: dict[str, Any]) -> Optional[str]:
    """Extract the operation name (dict or flattened string form)."""
    raw = record.get("operationName")
    if isinstance(raw, dict):
        value = raw.get("value")
        return str(value).strip() if isinstance(value, str) and value.strip() else None
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    flattened = record.get("operationName.value")
    if isinstance(flattened, str) and flattened.strip():
        return flattened.strip()
    return None


def _classify(operation: str) -> tuple[ActionCategory, OperationType]:
    """Map an Azure operation onto the canonical taxonomy.

    Curated table first; deterministic suffix rules (``/delete``,
    ``/write``) second. Anything else is out of scope — the caller
    skips it rather than guessing a category.
    """
    mapped = _OPERATION_MAP.get(operation)
    if mapped is not None:
        return mapped
    if operation.endswith("/delete"):
        return ActionCategory.DELETE, OperationType.SINGLE
    if operation.endswith("/write"):
        return ActionCategory.MODIFY, OperationType.SINGLE
    raise UnsupportedEventError(
        f"Azure operation not in destructive-activity scope: {operation}"
    )


def _segment_after(resource_id: str, marker: str) -> Optional[str]:
    """First path segment after ``marker`` (``/vaults/x/...`` -> ``x``)."""
    if marker not in resource_id:
        return None
    tail = resource_id.split(marker, 1)[1].lstrip("/")
    return tail.split("/", 1)[0] or None


def _parse_azure_resource(resource_id: str) -> dict[str, Optional[str]]:
    """Split an Azure resource manager id into its structural parts."""
    segments = [s for s in resource_id.split("/") if s]
    info: dict[str, Optional[str]] = {
        "subscription": None,
        "resource_group": None,
        "namespace": None,
        "type": None,
        "name": None,
    }
    index = 0
    while index < len(segments):
        lowered = segments[index].lower()
        if lowered == "subscriptions" and index + 1 < len(segments):
            info["subscription"] = segments[index + 1]
            index += 2
        elif lowered == "resourcegroups" and index + 1 < len(segments):
            info["resource_group"] = segments[index + 1]
            index += 2
        elif lowered == "providers" and index + 1 < len(segments):
            info["namespace"] = segments[index + 1]
            tail = segments[index + 2 :]
            info["type"] = tail[0] if tail else None
            info["name"] = tail[1] if len(tail) > 1 else None
            break
        else:
            index += 1
    return info


def _extract_actor(
    record: dict[str, Any], tracker: AvailabilityTracker
) -> tuple[Optional[str], ActorType]:
    """Azure ``caller`` -> (actor_id, actor_type).

    Caller identities carrying an inbox are user principals; the
    rest (service principals, managed identities) are mapped to
    ``ASSUMED_ROLE`` — never invented finer than the evidence.
    """
    caller = record.get("caller")
    if not isinstance(caller, str) or not caller.strip():
        tracker.unavailable("actor_id", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("actor_type", UnavailableReason.NOT_IN_SOURCE)
        return None, ActorType.UNKNOWN
    actor_id = caller.strip()
    if "@" in actor_id:
        actor_type = ActorType.IAM_USER
    else:
        actor_type = ActorType.ASSUMED_ROLE
    tracker.available("actor_id")
    tracker.available("actor_type")
    return actor_id, actor_type


def _enrich_from_catalog(
    catalog: Optional[ProtectionCatalog],
    resource_id: Optional[str],
    resource_arn: Optional[str],
    tracker: AvailabilityTracker,
) -> dict[str, Any]:
    """Overlay catalog facts; every unprovided field is recorded."""
    enriched: dict[str, Any] = {}
    state = None
    if catalog is not None:
        state = catalog.lookup(resource_arn or resource_id or "", None)
        if state is None and resource_id:
            state = catalog.lookup(resource_id, None)
    if state is None:
        for field_name in _PROTECTION_FIELDS:
            tracker.unavailable(field_name, UnavailableReason.ENRICHMENT_MISSING)
        return enriched
    if state.business_criticality is not None:
        enriched["business_criticality"] = state.business_criticality
    if state.sensitivity_level is not None:
        try:
            enriched["sensitivity_level"] = SensitivityLevel(state.sensitivity_level)
        except ValueError:
            enriched["sensitivity_level"] = None
    for field_name, value in (
        ("versioning_enabled", state.versioning_enabled),
        ("object_lock_enabled", state.object_lock_enabled),
        ("backup_enabled", state.backup_enabled),
        ("snapshot_protection_enabled", state.snapshot_protection_enabled),
        ("retention_period", state.retention_period),
    ):
        if value is not None:
            enriched[field_name] = value
    for field_name in _PROTECTION_FIELDS:
        if enriched.get(field_name) is not None:
            tracker.available(field_name, enriched=True)
        else:
            tracker.unavailable(field_name, UnavailableReason.ENRICHMENT_MISSING)
    return enriched


class AzureActivityLogNormalizer:
    """Normalizes Azure Activity Log records into canonical events."""

    def __init__(self, catalog: Optional[ProtectionCatalog] = None) -> None:
        self._catalog = catalog

    def normalize(
        self,
        record: dict[str, Any],
        *,
        raw_event_reference: Optional[str] = None,
        raw_record_index: Optional[int] = None,
        is_replayed: bool = False,
        is_synthetic: bool = False,
        generator: Optional[str] = None,
    ) -> ResourceActivityEvent:
        """Normalize one Activity Log record.

        Raises :class:`UnsupportedEventError` for valid records that
        are out of scope (other categories / unmapped operations).
        """
        if not isinstance(record, dict):
            raise MalformedEventError(
                "Azure Activity Log record must be a dict",
                provider="azure",
                raw_event=record,
            )

        missing = [
            name
            for name in ("time", "resourceId", "operationName")
            if record.get(name) is None and record.get(f"{name}.value") is None
        ]
        if missing:
            raise MalformedEventError(
                "Azure Activity Log record missing required fields",
                provider="azure",
                missing_fields=missing,
                raw_event=record,
            )

        timestamp = _parse_timestamp(record["time"])
        resource_id_raw = str(record["resourceId"]).strip()
        operation = _operation_name(record)
        if operation is None:
            raise MalformedEventError(
                "Azure record missing operationName.value",
                provider="azure",
                missing_fields=["operationName"],
                raw_event=record,
            )

        category = record.get("category")
        if isinstance(category, str) and category.strip() and (
            category.strip() not in _IN_SCOPE_CATEGORIES
        ):
            raise UnsupportedEventError(
                f"Azure category out of scope: {category.strip()}",
                context={"operation": operation},
            )

        action_category, operation_type = _classify(operation)

        tracker = AvailabilityTracker()
        tracker.available("event_id")
        tracker.available("timestamp")
        tracker.available("action_category")

        actor_id, actor_type = _extract_actor(record, tracker)

        account_id = record.get("subscriptionId")
        if not isinstance(account_id, str) or not account_id.strip():
            parsed = _parse_azure_resource(resource_id_raw)
            account_id = parsed["subscription"]
        if isinstance(account_id, str) and account_id.strip():
            tracker.available("account_id")
            account_id = account_id.strip()
        else:
            account_id = None
            tracker.unavailable("account_id", UnavailableReason.NOT_IN_SOURCE)

        region = record.get("location")
        if isinstance(region, str) and region.strip():
            tracker.available("region")
            region = region.strip()
        else:
            region = None
            tracker.unavailable("region", UnavailableReason.NOT_IN_SOURCE)

        # --- resource identity -------------------------------------------
        object_key: Optional[str] = None
        snapshot_id: Optional[str] = None
        recovery_point_id: Optional[str] = None
        canonical_resource_id: Optional[str] = None

        if "/blobs/" in resource_id_raw:
            container = _segment_after(resource_id_raw, "/containers/") or ""
            blob = resource_id_raw.split("/blobs/", 1)[1]
            object_key = f"{container}/{blob}" if container else blob
            canonical_resource_id = _segment_after(
                resource_id_raw, "/storageAccounts/"
            )
            tracker.available("object_key")
        elif "/containers/" in resource_id_raw:
            canonical_resource_id = _segment_after(resource_id_raw, "/containers/")
        elif "/recoveryPoints/" in resource_id_raw:
            recovery_point_id = _segment_after(resource_id_raw, "/recoveryPoints/")
            canonical_resource_id = recovery_point_id
            tracker.available("recovery_point_id")
        elif "/snapshots/" in resource_id_raw:
            snapshot_id = _segment_after(resource_id_raw, "/snapshots/")
            canonical_resource_id = snapshot_id
            tracker.available("snapshot_id")

        if canonical_resource_id is None:
            parsed = _parse_azure_resource(resource_id_raw)
            canonical_resource_id = parsed["name"]
        if canonical_resource_id:
            tracker.available("resource_id")
        else:
            tracker.unavailable("resource_id", UnavailableReason.NOT_IN_SOURCE)
        tracker.available("resource_arn")

        tracker.unavailable("object_count", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("bytes_changed", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("source_ip", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("user_agent", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("session_id", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("version_id", UnavailableReason.FIELD_NOT_APPLICABLE)
        tracker.unavailable("is_delete_marker", UnavailableReason.FIELD_NOT_APPLICABLE)
        tracker.unavailable("backup_vault_name", UnavailableReason.FIELD_NOT_APPLICABLE)
        if snapshot_id is None:
            tracker.unavailable("snapshot_id", UnavailableReason.NOT_IN_SOURCE)
        if recovery_point_id is None:
            tracker.unavailable("recovery_point_id", UnavailableReason.NOT_IN_SOURCE)
        if object_key is None:
            tracker.unavailable("object_key", UnavailableReason.NOT_IN_SOURCE)

        # --- deterministic event identity ---------------------------------
        correlation_id = record.get("correlationId")
        event_id = (
            str(correlation_id).strip()
            if isinstance(correlation_id, str) and correlation_id.strip()
            else f"azure-activity:{raw_event_reference or raw_record_index or 0}"
        )

        enriched = _enrich_from_catalog(
            self._catalog, canonical_resource_id, resource_id_raw, tracker
        )

        notes: list[str] = []
        result_type = record.get("resultType")
        if isinstance(result_type, str) and result_type.strip() and (
            result_type.strip() != "Succeeded"
        ):
            notes.append(f"operation resultType={result_type.strip()}")

        provenance = DataProvenance(
            source_type="azure_activity_log",
            ingestion_pipeline="azure.activity_log",
            raw_record_index=raw_record_index,
            raw_reference=raw_event_reference,
            is_replayed=is_replayed,
            is_synthetic=is_synthetic,
            generator=generator,
            normalizer_version=AZURE_NORMALIZER_VERSION,
            transformation_notes=tuple(notes),
        )

        params = record.get("properties")
        return ResourceActivityEvent(
            event_id=event_id,
            timestamp=timestamp,
            provider=CloudProvider.AZURE,
            account_id=account_id,
            region=region,
            actor_id=actor_id,
            actor_type=actor_type,
            session_id=None,
            resource_id=canonical_resource_id,
            resource_type=ResourceType.UNKNOWN,
            resource_arn=resource_id_raw,
            action=action_category.value,
            action_category=action_category,
            operation_type=operation_type,
            raw_action=operation,
            object_key=object_key,
            snapshot_id=snapshot_id,
            recovery_point_id=recovery_point_id,
            object_count=None,
            bytes_changed=None,
            source_ip=None,
            user_agent=None,
            business_criticality=enriched.get("business_criticality"),
            sensitivity_level=enriched.get("sensitivity_level"),
            versioning_enabled=enriched.get("versioning_enabled"),
            object_lock_enabled=enriched.get("object_lock_enabled"),
            backup_enabled=enriched.get("backup_enabled"),
            snapshot_protection_enabled=enriched.get("snapshot_protection_enabled"),
            retention_period=enriched.get("retention_period"),
            request_parameters=params if isinstance(params, dict) else None,
            raw_event_reference=raw_event_reference,
            feature_availability=tracker.to_tuple(),
            data_provenance=provenance,
        )


@dataclass
class IngestResult:
    """Outcome of one Azure ingestion batch."""

    events: list[ResourceActivityEvent] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    quarantined: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.events) + len(self.skipped) + len(self.quarantined)

    @property
    def ok(self) -> bool:
        return not self.quarantined


def _unwrap_records(payload: Any) -> list[dict[str, Any]]:
    """Accept ``[...]``, ``{"value": [...]}`` or ``{"records": [...]}``."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("value", "records", "Records"):
            inner = payload.get(key)
            if isinstance(inner, list):
                return inner
    raise MalformedEventError(
        "payload must be a list of records or {'value': [...]}",
        provider="azure",
        raw_event=payload if isinstance(payload, dict) else None,
    )


class AzureActivityLogIngestor:
    """Normalizes batches of Azure Activity Log records."""

    def __init__(
        self,
        catalog: Optional[ProtectionCatalog] = None,
        *,
        strict: bool = True,
        max_records_per_batch: int = 1000,
    ) -> None:
        self._catalog = catalog
        self._strict = strict
        self._max_records = max_records_per_batch

    def ingest_batch(
        self,
        payload: Any,
        *,
        is_replayed: bool = False,
        is_synthetic: bool = False,
        generator: Optional[str] = None,
    ) -> IngestResult:
        """Normalize a batch; returns per-record dispositions."""
        records = _unwrap_records(payload)
        if len(records) > self._max_records:
            raise MalformedEventError(
                f"batch exceeds max_records_per_batch ({self._max_records})",
                provider="azure",
                context={"got": len(records)},
            )

        normalizer = AzureActivityLogNormalizer(catalog=self._catalog)
        result = IngestResult()
        for index, record in enumerate(records):
            try:
                event = normalizer.normalize(
                    record,
                    raw_event_reference=raw_reference_for(record, index),
                    raw_record_index=index,
                    is_replayed=is_replayed,
                    is_synthetic=is_synthetic,
                    generator=generator,
                )
                result.events.append(event)
            except UnsupportedEventError:
                result.skipped.append({"index": index, "reason": "unsupported_event"})
            except MalformedEventError as exc:
                if self._strict:
                    raise
                result.quarantined.append(
                    {"index": index, "error": str(exc), "record": record}
                )
        return result


def raw_reference_for(record: dict[str, Any], index: int) -> str:
    """Stable pointer into the raw Azure record (never a payload copy)."""
    record_id = record.get("recordId") if isinstance(record, dict) else None
    correlation = record.get("correlationId") if isinstance(record, dict) else None
    identity = record_id or correlation or index
    return f"azure-activity://{identity}"


__all__ = [
    "AZURE_NORMALIZER_VERSION",
    "AzureActivityLogIngestor",
    "AzureActivityLogNormalizer",
    "IngestResult",
    "raw_reference_for",
]
