"""GCP Cloud Audit Logs -> canonical events ingestion (Part 5).

Normalizes GCP *Cloud Audit Log* entries (Admin Activity and
Data Access audit logs, delivered via Cloud Logging) into
canonical :class:`ResourceActivityEvent` records. Mirrors the
AWS CloudTrail and Azure Activity Log ingestor contracts:

- ``normalized``  — became a canonical event
- ``skipped``     — valid but out of scope (non-audit logs,
                    unmapped methods, read/create operations)
- ``quarantined`` — malformed; unusable as evidence

Design rules (inherited from the algorithm core):

1. **Nothing is invented.** Absent fields stay ``None`` with an
   availability record explaining why. Protection state comes only
   from a :class:`~detection.cloud_destruction.protection.ProtectionCatalog`
   — never from the method name.
2. **Raw actions are evidence.** ``raw_action`` keeps the full
   ``storage.objects.delete``-style method name next to the
   canonical category.
3. **Attempts are evidence.** A failed API call (``status.code``
   != 0) is still normalized — attempted destruction is
   detectable activity — and the failure is recorded as a
   provenance note.
4. **GCP types are not canonical types.** ``resource_type`` stays
   ``UNKNOWN`` unless the evidence supports a canonical mapping;
   the GCP resource name is preserved verbatim as
   ``resource_arn``.
5. **Operations are correlation evidence.** GCP's ``operation.id``
   groups the entries of one API operation chain; it feeds the
   canonical ``session_id`` when present.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from detection.cloud_destruction.provenance import (
    AvailabilityTracker,
    DataProvenance,
    UnavailableReason,
)
from detection.cloud_destruction.protection import ProtectionCatalog
from detection.cloud_destruction.schemas import (
    ActionCategory,
    ActorType,
    BusinessCriticality,
    CloudProvider,
    OperationType,
    ResourceActivityEvent,
    ResourceType,
    SensitivityLevel,
)

#: Bumped when the GCP method mapping changes.
GCP_NORMALIZER_VERSION = "1.0.0"

#: Curated GCP method name -> (canonical category, operation nuance).
_OPERATION_MAP: dict[str, tuple[ActionCategory, OperationType]] = {
    # --- Cloud Storage --------------------------------------------------
    "storage.objects.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "storage.objects.copy": (ActionCategory.REWRITE, OperationType.SINGLE),
    "storage.objects.update": (ActionCategory.MODIFY, OperationType.SINGLE),
    "storage.objects.undelete": (ActionCategory.RESTORE, OperationType.SINGLE),
    "storage.buckets.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "storage.buckets.update": (ActionCategory.MODIFY, OperationType.SINGLE),
    "storage.buckets.setIamPolicy": (
        ActionCategory.POLICY_CHANGE,
        OperationType.SINGLE,
    ),
    "storage.buckets.lockRetentionPolicy": (
        ActionCategory.PROTECTION_CHANGE,
        OperationType.SINGLE,
    ),
    # --- Compute ---------------------------------------------------------
    "compute.instances.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "compute.disks.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "compute.disks.copy": (ActionCategory.REWRITE, OperationType.SINGLE),
    "compute.snapshots.delete": (
        ActionCategory.SNAPSHOT_DELETE,
        OperationType.SINGLE,
    ),
    # --- Data services ----------------------------------------------------
    "sql.instances.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "bigquery.tables.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "bigquery.datasets.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "spanner.databases.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "datastore.entities.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    "firestore.documents.delete": (ActionCategory.DELETE, OperationType.SINGLE),
    # --- IAM (policy plane) -----------------------------------------------
    "iam.roles.delete": (ActionCategory.POLICY_CHANGE, OperationType.SINGLE),
    "iam.roles.update": (ActionCategory.POLICY_CHANGE, OperationType.SINGLE),
    "iam.serviceAccounts.delete": (ActionCategory.DELETE, OperationType.SINGLE),
}

#: Method-name segments that classify a ``.delete`` method.
_SNAPSHOT_SEGMENTS = frozenset(
    {"snapshot", "snapshots", "diskSnapshot", "diskSnapshots"}
)
_BACKUP_SEGMENTS = frozenset({"backup", "backups"})
_RECOVERY_POINT_SEGMENTS = frozenset(
    {"recoverypoint", "recoverypoints", "recovery_point", "recovery_points"}
)

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

# GCP timestamps: RFC 3339, e.g. ``2024-01-02T03:04:05.123456Z``.
_GCP_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)

#: Label keys used as canonical resource-id fallbacks, in priority order.
_RESOURCE_LABEL_KEYS = (
    "bucket_name",
    "instance_name",
    "disk_name",
    "snapshot_name",
    "database_id",
    "table_id",
    "cluster_name",
    "project_id",
)


def _parse_timestamp(raw: Any) -> datetime:
    """Parse a GCP RFC-3339 ``timestamp`` into aware UTC."""
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not isinstance(raw, str):
        raise MalformedEventError(
            "GCP 'timestamp' must be an RFC-3339 string",
            provider="gcp",
            missing_fields=["timestamp"],
        )
    match = _GCP_TS_RE.match(raw.strip())
    if match is None:
        raise MalformedEventError(
            f"unparsable GCP timestamp {raw!r}",
            provider="gcp",
            missing_fields=["timestamp"],
        )
    base, fraction, zone = match.groups()
    # Python's fromisoformat accepts at most 6 fractional digits.
    fraction = fraction[:7] if fraction else ""
    zone = "+00:00" if zone in (None, "Z") else zone.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(f"{base}{fraction}{zone}")
    except ValueError as exc:
        raise MalformedEventError(
            f"unparsable GCP timestamp {raw!r}",
            provider="gcp",
            missing_fields=["timestamp"],
            cause=exc,
        ) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _proto_payload(record: dict[str, Any]) -> dict[str, Any]:
    payload = record.get("protoPayload")
    if not isinstance(payload, dict):
        raise MalformedEventError(
            "GCP record missing protoPayload object",
            provider="gcp",
            missing_fields=["protoPayload"],
            raw_event=record,
        )
    return payload


def _method_name(payload: dict[str, Any]) -> str:
    raw = payload.get("methodName")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    raise MalformedEventError(
        "GCP protoPayload missing methodName",
        provider="gcp",
        missing_fields=["methodName"],
    )


def _classify(method: str) -> tuple[ActionCategory, OperationType]:
    """Map a GCP method onto the canonical taxonomy.

    Curated table first; deterministic suffix rules (``.delete``,
    ``.update``, ``.setIamPolicy`` ...) second. Anything else is
    out of scope — the caller skips it rather than guessing a
    category.
    """
    mapped = _OPERATION_MAP.get(method)
    if mapped is not None:
        return mapped
    segments = method.split(".")
    tail = segments[-1]
    previous = segments[-2] if len(segments) >= 2 else ""
    if tail == "delete":
        if previous in _SNAPSHOT_SEGMENTS:
            return ActionCategory.SNAPSHOT_DELETE, OperationType.SINGLE
        if previous in _BACKUP_SEGMENTS:
            return ActionCategory.BACKUP_DELETE, OperationType.SINGLE
        if previous.lower() in _RECOVERY_POINT_SEGMENTS:
            return ActionCategory.RECOVERY_POINT_DELETE, OperationType.SINGLE
        return ActionCategory.DELETE, OperationType.SINGLE
    if tail in {"undelete", "restore"}:
        return ActionCategory.RESTORE, OperationType.SINGLE
    if tail in {"update", "patch"}:
        return ActionCategory.MODIFY, OperationType.SINGLE
    if tail == "setIamPolicy":
        return ActionCategory.POLICY_CHANGE, OperationType.SINGLE
    if tail == "lockRetentionPolicy":
        return ActionCategory.PROTECTION_CHANGE, OperationType.SINGLE
    if tail == "copy":
        return ActionCategory.REWRITE, OperationType.SINGLE
    raise UnsupportedEventError(
        f"GCP method not in destructive-activity scope: {method}"
    )


def _segment_after(resource_name: str, marker: str) -> Optional[str]:
    """First path segment after ``marker`` (``/buckets/x/...`` -> ``x``)."""
    if marker not in resource_name:
        return None
    tail = resource_name.split(marker, 1)[1].lstrip("/")
    return tail.split("/", 1)[0] or None


def _parse_resource_name(resource_name: str) -> dict[str, Optional[str]]:
    """Extract canonical identifiers from a GCP resource name.

    Examples: ``projects/_/buckets/b/objects/o``,
    ``projects/p/zones/z/instances/i``, ``projects/p/global/snapshots/s``.
    """
    info: dict[str, Optional[str]] = {
        "object_key": None,
        "bucket": None,
        "snapshot_id": None,
        "canonical": None,
    }
    if "/objects/" in resource_name:
        bucket = _segment_after(resource_name, "/buckets/")
        object_key = resource_name.split("/objects/", 1)[1]
        info["object_key"] = object_key or None
        info["bucket"] = bucket
        info["canonical"] = bucket or object_key
        return info
    if "/buckets/" in resource_name:
        bucket = _segment_after(resource_name, "/buckets/")
        info["bucket"] = bucket
        info["canonical"] = bucket
        return info
    if "/snapshots/" in resource_name:
        snapshot = _segment_after(resource_name, "/snapshots/")
        info["snapshot_id"] = snapshot
        info["canonical"] = snapshot
        return info
    for marker in ("/disks/", "/instances/", "/databases/", "/tables/", "/clusters/"):
        if marker in resource_name:
            info["canonical"] = _segment_after(resource_name, marker)
            return info
    # Unknown shape: fall back to the last non-empty path segment.
    segments = [s for s in resource_name.split("/") if s]
    info["canonical"] = segments[-1] if segments else None
    return info


def _extract_actor(
    payload: dict[str, Any], tracker: AvailabilityTracker
) -> tuple[Optional[str], ActorType]:
    """GCP ``authenticationInfo`` -> (actor_id, actor_type).

    Google service-account addresses end in ``.gserviceaccount.com``
    and map to ``SERVICE_ACCOUNT``; other principal emails are user
    principals. A principal with no address evidence stays UNKNOWN.
    """
    auth = payload.get("authenticationInfo")
    principal: Any = None
    if isinstance(auth, dict):
        principal = auth.get("principalEmail") or auth.get("principalSubject")
    if not isinstance(principal, str) or not principal.strip():
        tracker.unavailable("actor_id", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("actor_type", UnavailableReason.NOT_IN_SOURCE)
        return None, ActorType.UNKNOWN
    actor_id = principal.strip()
    if actor_id.endswith(".gserviceaccount.com"):
        actor_type = ActorType.SERVICE_ACCOUNT
    elif "@" in actor_id:
        actor_type = ActorType.IAM_USER
    else:
        actor_type = ActorType.ASSUMED_ROLE
    tracker.available("actor_id")
    tracker.available("actor_type")
    return actor_id, actor_type


def _project_id(record: dict[str, Any]) -> Optional[str]:
    """Project identity from resource labels or the logName path."""
    resource = record.get("resource")
    if isinstance(resource, dict):
        labels = resource.get("labels")
        if isinstance(labels, dict):
            project = labels.get("project_id")
            if isinstance(project, str) and project.strip():
                return project.strip()
    log_name = record.get("logName")
    if isinstance(log_name, str):
        segments = log_name.split("/")
        if "projects" in segments:
            index = segments.index("projects")
            if index + 1 < len(segments):
                candidate = segments[index + 1]
                if candidate.strip():
                    return candidate.strip()
    return None


def _region(record: dict[str, Any]) -> Optional[str]:
    resource = record.get("resource")
    if isinstance(resource, dict):
        labels = resource.get("labels")
        if isinstance(labels, dict):
            location = labels.get("location")
            if isinstance(location, str) and location.strip():
                return location.strip()
    payload = record.get("protoPayload")
    if isinstance(payload, dict):
        locations = payload.get("resourceLocation")
        if isinstance(locations, dict):
            current = locations.get("currentLocations")
            if isinstance(current, list) and current:
                first = current[0]
                if isinstance(first, str) and first.strip():
                    return first.strip()
    return None


def _enrich_from_catalog(
    catalog: Optional[ProtectionCatalog],
    canonical_resource_id: Optional[str],
    resource_arn: Optional[str],
    tracker: AvailabilityTracker,
) -> dict[str, Any]:
    """Overlay catalog facts; every unprovided field is recorded."""
    enriched: dict[str, Any] = {}
    state = None
    if catalog is not None:
        state = catalog.lookup(resource_arn or canonical_resource_id or "", None)
        if state is None and canonical_resource_id:
            state = catalog.lookup(canonical_resource_id, None)
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


class GcpAuditLogNormalizer:
    """Normalizes GCP Cloud Audit Log entries into canonical events."""

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
        """Normalize one audit log entry.

        Raises :class:`UnsupportedEventError` for valid records that
        are out of scope (non-audit logs, unmapped methods).
        """
        if not isinstance(record, dict):
            raise MalformedEventError(
                "GCP audit log entry must be a dict",
                provider="gcp",
                raw_event=record,
            )

        log_name = record.get("logName")
        if isinstance(log_name, str) and log_name.strip():
            if "cloudaudit.googleapis.com" not in log_name:
                raise UnsupportedEventError(
                    f"GCP log is not a Cloud Audit Log: {log_name.strip()}",
                    context={"logName": log_name},
                )

        payload = _proto_payload(record)
        method = _method_name(payload)
        timestamp = _parse_timestamp(record.get("timestamp"))
        resource_name_raw = payload.get("resourceName")
        if isinstance(resource_name_raw, str) and resource_name_raw.strip():
            resource_name = resource_name_raw.strip()
        else:
            resource_name = None

        # Non-audit-log sanity: the payload type marker, when present,
        # must be an AuditLog.
        payload_type = payload.get("@type")
        if isinstance(payload_type, str) and payload_type.strip():
            if "AuditLog" not in payload_type:
                raise UnsupportedEventError(
                    f"GCP protoPayload is not an AuditLog: {payload_type.strip()}",
                    context={"methodName": method},
                )

        category, operation_type = _classify(method)

        tracker = AvailabilityTracker()
        tracker.available("event_id")
        tracker.available("timestamp")
        tracker.available("action_category")

        actor_id, actor_type = _extract_actor(payload, tracker)

        account_id = _project_id(record)
        if account_id is not None:
            tracker.available("account_id")
        else:
            tracker.unavailable("account_id", UnavailableReason.NOT_IN_SOURCE)

        region = _region(record)
        if region is not None:
            tracker.available("region")
        else:
            tracker.unavailable("region", UnavailableReason.NOT_IN_SOURCE)

        # --- resource identity -------------------------------------------
        object_key: Optional[str] = None
        snapshot_id: Optional[str] = None
        canonical_resource_id: Optional[str] = None
        if resource_name is not None:
            parsed = _parse_resource_name(resource_name)
            object_key = parsed["object_key"]
            snapshot_id = parsed["snapshot_id"]
            canonical_resource_id = parsed["canonical"]
        if canonical_resource_id is None:
            resource = record.get("resource")
            labels = resource.get("labels") if isinstance(resource, dict) else None
            if isinstance(labels, dict):
                for key in _RESOURCE_LABEL_KEYS:
                    value = labels.get(key)
                    if isinstance(value, str) and value.strip():
                        canonical_resource_id = value.strip()
                        break
        if canonical_resource_id is not None:
            tracker.available("resource_id")
        else:
            tracker.unavailable("resource_id", UnavailableReason.NOT_IN_SOURCE)
        tracker.available("resource_arn")

        tracker.unavailable("object_count", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("bytes_changed", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("backup_vault_name", UnavailableReason.FIELD_NOT_APPLICABLE)
        tracker.unavailable("version_id", UnavailableReason.FIELD_NOT_APPLICABLE)
        tracker.unavailable("is_delete_marker", UnavailableReason.FIELD_NOT_APPLICABLE)
        if object_key is None:
            tracker.unavailable("object_key", UnavailableReason.NOT_IN_SOURCE)
        if snapshot_id is None:
            tracker.unavailable("snapshot_id", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("recovery_point_id", UnavailableReason.NOT_IN_SOURCE)

        # GCP's operation.id correlates the entries of one operation
        # chain — it is genuine session-correlation evidence.
        operation = payload.get("operation")
        session_id: Optional[str] = None
        if isinstance(operation, dict):
            operation_id = operation.get("id")
            if isinstance(operation_id, str) and operation_id.strip():
                session_id = operation_id.strip()
        if session_id is not None:
            tracker.available("session_id")
        else:
            tracker.unavailable("session_id", UnavailableReason.NOT_IN_SOURCE)

        # --- network evidence (GCP audit logs carry it) -------------------
        request_metadata = payload.get("requestMetadata")
        source_ip: Optional[str] = None
        user_agent: Optional[str] = None
        if isinstance(request_metadata, dict):
            caller_ip = request_metadata.get("callerIp")
            if isinstance(caller_ip, str) and caller_ip.strip():
                source_ip = caller_ip.strip()
                tracker.available("source_ip")
            else:
                tracker.unavailable("source_ip", UnavailableReason.NOT_IN_SOURCE)
            agent = request_metadata.get("callerSuppliedUserAgent")
            if isinstance(agent, str) and agent.strip():
                user_agent = agent.strip()
                tracker.available("user_agent")
            else:
                tracker.unavailable("user_agent", UnavailableReason.NOT_IN_SOURCE)
        else:
            tracker.unavailable("source_ip", UnavailableReason.NOT_IN_SOURCE)
            tracker.unavailable("user_agent", UnavailableReason.NOT_IN_SOURCE)

        # --- deterministic event identity ----------------------------------
        insert_id = record.get("insertId")
        if isinstance(insert_id, str) and insert_id.strip():
            event_id = insert_id.strip()
        else:
            identity = hashlib.sha256(
                f"{method}|{resource_name or ''}|{timestamp.isoformat()}".encode(
                    "utf-8"
                )
            ).hexdigest()[:16]
            event_id = f"gcp-audit:{raw_event_reference or raw_record_index or identity}"

        enriched = _enrich_from_catalog(
            self._catalog, canonical_resource_id, resource_name, tracker
        )

        notes: list[str] = []
        status = payload.get("status")
        if isinstance(status, dict):
            code = status.get("code")
            if isinstance(code, int) and code != 0:
                notes.append(f"operation status.code={code}")

        provenance = DataProvenance(
            source_type="gcp_audit_log",
            ingestion_pipeline="gcp.audit_log",
            raw_record_index=raw_record_index,
            raw_reference=raw_event_reference,
            is_replayed=is_replayed,
            is_synthetic=is_synthetic,
            generator=generator,
            normalizer_version=GCP_NORMALIZER_VERSION,
            transformation_notes=tuple(notes),
        )

        request = payload.get("request")
        return ResourceActivityEvent(
            event_id=event_id,
            timestamp=timestamp,
            provider=CloudProvider.GCP,
            account_id=account_id,
            region=region,
            actor_id=actor_id,
            actor_type=actor_type,
            session_id=session_id,
            resource_id=canonical_resource_id,
            resource_type=ResourceType.UNKNOWN,
            resource_arn=resource_name,
            action=category.value,
            action_category=category,
            operation_type=operation_type,
            raw_action=method,
            object_key=object_key,
            snapshot_id=snapshot_id,
            recovery_point_id=None,
            object_count=None,
            bytes_changed=None,
            source_ip=source_ip,
            user_agent=user_agent,
            business_criticality=enriched.get("business_criticality"),
            sensitivity_level=enriched.get("sensitivity_level"),
            versioning_enabled=enriched.get("versioning_enabled"),
            object_lock_enabled=enriched.get("object_lock_enabled"),
            backup_enabled=enriched.get("backup_enabled"),
            snapshot_protection_enabled=enriched.get("snapshot_protection_enabled"),
            retention_period=enriched.get("retention_period"),
            request_parameters=request if isinstance(request, dict) else None,
            raw_event_reference=raw_event_reference,
            feature_availability=tracker.to_tuple(),
            data_provenance=provenance,
        )


@dataclass
class IngestResult:
    """Outcome of one GCP ingestion batch."""

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
    """Accept ``[...]`` or ``{"entries": [...]}`` (Cloud Logging API)."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("entries", "auditLogs", "audit_logs"):
            inner = payload.get(key)
            if isinstance(inner, list):
                return inner
    raise MalformedEventError(
        "payload must be a list of entries or {'entries': [...]}",
        provider="gcp",
        raw_event=payload if isinstance(payload, dict) else None,
    )


class GcpAuditLogIngestor:
    """Normalizes batches of GCP Cloud Audit Log entries."""

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
                provider="gcp",
                context={"got": len(records)},
            )

        normalizer = GcpAuditLogNormalizer(catalog=self._catalog)
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
    """Stable pointer into the raw GCP record (never a payload copy)."""
    insert_id = record.get("insertId") if isinstance(record, dict) else None
    log_name = record.get("logName") if isinstance(record, dict) else None
    identity = insert_id or log_name or index
    return f"gcp-audit://{identity}"


__all__ = [
    "GCP_NORMALIZER_VERSION",
    "GcpAuditLogIngestor",
    "GcpAuditLogNormalizer",
    "IngestResult",
    "raw_reference_for",
]
