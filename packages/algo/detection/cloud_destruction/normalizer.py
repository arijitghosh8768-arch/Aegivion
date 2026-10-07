"""Normalizers: provider telemetry → canonical :class:`ResourceActivityEvent`.

AWS CloudTrail is the first supported source. Structure mirrors Algorithm #2:
a provider dispatch entry point, a generic canonical-input path (fixtures /
other clouds), and one provider-specific implementation.

Normalizing rules:

1. **Nothing is invented.** A field absent from telemetry stays ``None`` and
   the event's ``feature_availability`` records the reason.
2. **Raw actions are evidence.** ``raw_action`` keeps the provider-specific
   event name; ``action_category`` holds the canonical taxonomy value.
3. Structural problems raise :class:`MalformedEventError`; valid-but-out-of-scope
   events raise :class:`UnsupportedEventError` (callers skip those without
   counting them as malformed).
4. Protection state is never guessed by the normalizer — it is enriched only
   from a :class:`~detection.cloud_destruction.protection.ProtectionCatalog`.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from detection.cloud_destruction.config import NORMALIZER_VERSION
from detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from detection.cloud_destruction.protection import ProtectionCatalog, ProtectionState
from detection.cloud_destruction.provenance import (
    AvailabilityTracker,
    DataProvenance,
    UnavailableReason,
)
from detection.cloud_destruction.schemas import (
    ActionCategory,
    ActorType,
    BusinessCriticality,
    CloudProvider,
    OperationType,
    ResourceActivityEvent,
    ResourceType,
    SensitivityLevel,
    map_resource_type,
)

# --------------------------------------------------------------------------- #
# Timestamp parsing
# --------------------------------------------------------------------------- #

_TIMESTAMP_KEYS = ("eventTime", "timestamp", "time", "event_timestamp")


def _parse_timestamp(value: Any) -> datetime:
    """Parse CloudTrail ``eventTime`` (or ISO-8601 / epoch) into aware UTC."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise MalformedEventError(
                f"timestamp out of range: {value!r}", missing_fields=["timestamp"], cause=exc
            ) from exc
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise MalformedEventError(
                f"unparsable timestamp {value!r}", missing_fields=["timestamp"], cause=exc
            ) from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise MalformedEventError("missing or invalid timestamp", missing_fields=["timestamp"])


def _extract_timestamp(record: dict[str, Any]) -> datetime:
    for key in _TIMESTAMP_KEYS:
        if record.get(key) is not None:
            return _parse_timestamp(record[key])
    raise MalformedEventError(
        "no timestamp field present", missing_fields=list(_TIMESTAMP_KEYS)
    )


# --------------------------------------------------------------------------- #
# Action taxonomy mapping
# --------------------------------------------------------------------------- #

ActionMapping = tuple[ActionCategory, OperationType, ResourceType]

#: (event_source, event_name) -> (category, operation, implied resource type).
#: ``event_source`` is the bare service namespace (``s3``, ``ec2``, ...).
_ACTION_MAP: dict[tuple[str, str], ActionMapping] = {
    # --- S3 data events -----------------------------------------------------
    ("s3", "PutObject"): (ActionCategory.CREATE, OperationType.SINGLE, ResourceType.S3_OBJECT),
    ("s3", "CompleteMultipartUpload"): (ActionCategory.CREATE, OperationType.SINGLE, ResourceType.S3_OBJECT),
    ("s3", "CopyObject"): (ActionCategory.REWRITE, OperationType.SINGLE, ResourceType.S3_OBJECT),
    ("s3", "DeleteObject"): (ActionCategory.DELETE, OperationType.SINGLE, ResourceType.S3_OBJECT),
    ("s3", "DeleteObjects"): (ActionCategory.DELETE, OperationType.BATCH, ResourceType.S3_OBJECT),
    ("s3", "DeleteObjectVersion"): (ActionCategory.VERSION_DELETE, OperationType.VERSIONED, ResourceType.S3_OBJECT),
    ("s3", "DeleteObjectVersionTagging"): (ActionCategory.VERSION_DELETE, OperationType.VERSIONED, ResourceType.S3_OBJECT),
    # --- S3 control / protection events --------------------------------------
    ("s3", "PutBucketVersioning"): (ActionCategory.PROTECTION_CHANGE, OperationType.SINGLE, ResourceType.S3_BUCKET),
    ("s3", "PutBucketObjectLockConfiguration"): (ActionCategory.PROTECTION_CHANGE, OperationType.SINGLE, ResourceType.S3_BUCKET),
    ("s3", "PutBucketLifecycleConfiguration"): (ActionCategory.PROTECTION_CHANGE, OperationType.SINGLE, ResourceType.S3_BUCKET),
    ("s3", "DeleteBucketLifecycleConfiguration"): (ActionCategory.PROTECTION_CHANGE, OperationType.SINGLE, ResourceType.S3_BUCKET),
    ("s3", "PutBucketPolicy"): (ActionCategory.POLICY_CHANGE, OperationType.SINGLE, ResourceType.S3_BUCKET),
    ("s3", "DeleteBucketPolicy"): (ActionCategory.POLICY_CHANGE, OperationType.SINGLE, ResourceType.S3_BUCKET),
    ("s3", "PutBucketAcl"): (ActionCategory.SHARE_CHANGE, OperationType.SINGLE, ResourceType.S3_BUCKET),
    # --- EBS ---------------------------------------------------------------
    ("ec2", "DeleteSnapshot"): (ActionCategory.SNAPSHOT_DELETE, OperationType.SINGLE, ResourceType.EBS_SNAPSHOT),
    ("ec2", "DeleteVolume"): (ActionCategory.DELETE, OperationType.SINGLE, ResourceType.EBS_VOLUME),
    ("ec2", "TerminateInstances"): (ActionCategory.DELETE, OperationType.BATCH, ResourceType.EC2_INSTANCE),
    # --- RDS -----------------------------------------------------------------
    ("rds", "DeleteDBSnapshot"): (ActionCategory.SNAPSHOT_DELETE, OperationType.SINGLE, ResourceType.RDS_SNAPSHOT),
    ("rds", "DeleteDBClusterSnapshot"): (ActionCategory.SNAPSHOT_DELETE, OperationType.SINGLE, ResourceType.RDS_SNAPSHOT),
    ("rds", "DeleteDBInstance"): (ActionCategory.DELETE, OperationType.SINGLE, ResourceType.RDS_INSTANCE),
    # --- AWS Backup --------------------------------------------------------------
    ("backup", "DeleteRecoveryPoint"): (ActionCategory.RECOVERY_POINT_DELETE, OperationType.SINGLE, ResourceType.RECOVERY_POINT),
    ("backup", "DeleteBackupVault"): (ActionCategory.BACKUP_DELETE, OperationType.SINGLE, ResourceType.BACKUP_VAULT),
    ("backup", "UpdateRecoveryPointLifecycle"): (ActionCategory.PROTECTION_CHANGE, OperationType.SINGLE, ResourceType.RECOVERY_POINT),
    ("backup", "PutBackupVaultLockConfiguration"): (ActionCategory.PROTECTION_CHANGE, OperationType.SINGLE, ResourceType.BACKUP_VAULT),
    ("backup", "DeleteBackupVaultLockConfiguration"): (ActionCategory.PROTECTION_CHANGE, OperationType.SINGLE, ResourceType.BACKUP_VAULT),
    ("backup", "PutBackupVaultAccessPolicy"): (ActionCategory.POLICY_CHANGE, OperationType.SINGLE, ResourceType.BACKUP_VAULT),
    ("backup", "DeleteBackupVaultAccessPolicy"): (ActionCategory.POLICY_CHANGE, OperationType.SINGLE, ResourceType.BACKUP_VAULT),
    ("backup", "StartRestoreJob"): (ActionCategory.RESTORE, OperationType.SINGLE, ResourceType.RECOVERY_POINT),
}


def classify_action(
    event_source: str, event_name: str
) -> Optional[ActionMapping]:
    """Map a raw ``eventSource``/``eventName`` pair to the canonical taxonomy.

    Returns ``None`` when the pair is not part of the destructive-activity
    scope (the caller then treats it as unsupported, not malformed).
    """
    source = (event_source or "").strip().lower()
    if source.endswith(".amazonaws.com"):
        source = source[: -len(".amazonaws.com")]
    return _ACTION_MAP.get((source, (event_name or "").strip()))


# --------------------------------------------------------------------------- #
# Actor extraction
# --------------------------------------------------------------------------- #

_IDENTITY_TYPE_MAP: dict[str, ActorType] = {
    "IAMUser": ActorType.IAM_USER,
    "AssumedRole": ActorType.ASSUMED_ROLE,
    "SourcedByAssumedRole": ActorType.ASSUMED_ROLE,
    "Root": ActorType.ROOT,
    "FederatedUser": ActorType.FEDERATED_USER,
    "AWSService": ActorType.AWS_SERVICE,
    "ServiceAccount": ActorType.SERVICE_ACCOUNT,
}


def _extract_actor(
    record: dict[str, Any], tracker: AvailabilityTracker
) -> tuple[Optional[str], ActorType, Optional[str]]:
    """Return ``(actor_id, actor_type, session_id)`` from ``userIdentity``."""
    identity = record.get("userIdentity")
    if not isinstance(identity, dict):
        tracker.unavailable("actor_id", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("actor_type", UnavailableReason.NOT_IN_SOURCE)
        tracker.unavailable("session_id", UnavailableReason.NOT_IN_SOURCE)
        return None, ActorType.UNKNOWN, None

    raw_type = str(identity.get("type") or "")
    actor_type = _IDENTITY_TYPE_MAP.get(raw_type, ActorType.UNKNOWN)
    if raw_type and actor_type is ActorType.UNKNOWN:
        tracker.unavailable("actor_type", UnavailableReason.PARSE_FAILURE, detail=f"unmapped type {raw_type!r}")
    else:
        tracker.available("actor_type")

    actor_id: Optional[str] = None
    for key in ("arn", "principalId", "userName"):
        value = identity.get(key)
        if isinstance(value, str) and value.strip():
            actor_id = value.strip()
            break
    if actor_type is ActorType.ROOT and actor_id is None:
        account = record.get("recipientAccountId") or identity.get("accountId")
        actor_id = f"root:{account}" if account else "root"

    session_id: Optional[str] = None
    session_context = identity.get("sessionContext")
    if isinstance(session_context, dict):
        issuer = session_context.get("sessionIssuer")
        if isinstance(issuer, dict):
            issuer_name = issuer.get("userName")
            if isinstance(issuer_name, str) and issuer_name.strip():
                session_id = issuer_name.strip()

    if actor_id:
        tracker.available("actor_id")
    else:
        tracker.unavailable("actor_id", UnavailableReason.NOT_IN_SOURCE)
    if session_id:
        tracker.available("session_id")
    else:
        tracker.unavailable("session_id", UnavailableReason.NOT_IN_SOURCE)
    return actor_id, actor_type, session_id


# --------------------------------------------------------------------------- #
# Resource extraction
# --------------------------------------------------------------------------- #

_ARN_RE = re.compile(
    r"^arn:(?P<partition>[^:]+):(?P<service>[^:]*):(?P<region>[^:]*):(?P<account>[^:]*):(?P<rest>.+)$"
)


def _extract_resources(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the ``resources`` list from a CloudTrail record (may be empty)."""
    resources = record.get("resources")
    if isinstance(resources, list):
        return [item for item in resources if isinstance(item, dict)]
    return []


def _resource_id_from_arn(arn: str) -> Optional[str]:
    """Terminal id of an ARN: ``...:snapshot/snap-123`` -> ``snap-123``.

    Backup ARNs nest paths (``backup-vault:v/recovery-point/rp-1``); the
    terminal segment after the last ``/`` (or ``:``) is the resource id.
    """
    match = _ARN_RE.match(arn)
    rest = match.group("rest") if match else arn
    if arn.lower().startswith("arn:aws:s3"):
        return rest.split("/", 1)[0] or None
    if "/" in rest:
        rest = rest.rsplit("/", 1)[-1]
    elif ":" in rest:
        rest = rest.rsplit(":", 1)[-1]
    return rest or None


def _extract_s3_target(
    record: dict[str, Any], tracker: AvailabilityTracker
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Return ``(resource_id, resource_arn, object_key)`` for S3 activity."""
    params = record.get("requestParameters") if isinstance(record.get("requestParameters"), dict) else {}
    bucket = params.get("bucketName") or params.get("bucket")
    object_key = params.get("key")

    arn: Optional[str] = None
    for resource in _extract_resources(record):
        candidate = resource.get("ARN") or resource.get("arn")
        if isinstance(candidate, str) and candidate.startswith("arn:aws:s3:::"):
            arn = candidate
            break

    if arn and not object_key:
        tail = arn.split(":::", 1)[-1]
        if "/" in tail:
            bucket, object_key = tail.split("/", 1)
    resource_id = str(bucket).strip() if bucket else None
    if not resource_id and arn:
        resource_id = arn.split(":::", 1)[-1].split("/", 1)[0] or None
    if resource_id:
        tracker.available("resource_id")
    else:
        tracker.unavailable("resource_id", UnavailableReason.NOT_IN_SOURCE)
    if object_key:
        tracker.available("object_key")
    else:
        tracker.unavailable("object_key", UnavailableReason.NOT_IN_SOURCE)
    return resource_id, arn, object_key


def _extract_arn_target(
    record: dict[str, Any], tracker: AvailabilityTracker
) -> tuple[Optional[str], Optional[str], ResourceType]:
    """Extract ``(resource_id, resource_arn, resource_type)`` from ARNs/params."""
    params = record.get("requestParameters") if isinstance(record.get("requestParameters"), dict) else {}

    resource_id: Optional[str] = None
    resource_arn: Optional[str] = None
    for resource in _extract_resources(record):
        candidate = resource.get("ARN") or resource.get("arn")
        if isinstance(candidate, str) and candidate.startswith("arn:"):
            resource_arn = candidate
            resource_id = _resource_id_from_arn(candidate)
            break

    if resource_id is None:
        # Common parameter names that identify the target resource.
        for key in (
            "snapshotId",
            "volumeId",
            "DBSnapshotIdentifier",
            "DBInstanceIdentifier",
            "recoveryPointArn",
            "RecoveryPointArn",
            "backupVaultName",
            "BackupVaultName",
        ):
            value = params.get(key)
            if isinstance(value, str) and value.strip():
                resource_id = value.strip()
                break

    resource_type = map_resource_type(resource_arn) if resource_arn else ResourceType.UNKNOWN
    if resource_type is ResourceType.UNKNOWN and resource_id:
        # Fall back on well-known id prefixes / parameter names — evidence, not invention.
        lowered = resource_id.lower()
        if lowered.startswith("snap-"):
            resource_type = ResourceType.EBS_SNAPSHOT
        elif lowered.startswith("vol-"):
            resource_type = ResourceType.EBS_VOLUME
        elif lowered.startswith("arn:aws:backup"):
            resource_type = ResourceType.RECOVERY_POINT
        elif "vault" in lowered:
            resource_type = ResourceType.BACKUP_VAULT

    if resource_id:
        tracker.available("resource_id")
    else:
        tracker.unavailable("resource_id", UnavailableReason.NOT_IN_SOURCE)
    if resource_arn:
        tracker.available("resource_arn")
    else:
        tracker.unavailable("resource_arn", UnavailableReason.NOT_IN_SOURCE)
    return resource_id, resource_arn, resource_type


def _extract_snapshot_id(record: dict[str, Any], tracker: AvailabilityTracker) -> Optional[str]:
    params = record.get("requestParameters") if isinstance(record.get("requestParameters"), dict) else {}
    for key in ("snapshotId", "DBSnapshotIdentifier", "DBClusterSnapshotIdentifier"):
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            tracker.available("snapshot_id")
            return value.strip()
    for resource in _extract_resources(record):
        arn = resource.get("ARN") or resource.get("arn")
        if isinstance(arn, str) and ("snapshot" in arn):
            tracker.available("snapshot_id")
            return _resource_id_from_arn(arn)
    tracker.unavailable("snapshot_id", UnavailableReason.NOT_IN_SOURCE)
    return None


def _extract_recovery_point(
    record: dict[str, Any], tracker: AvailabilityTracker
) -> tuple[Optional[str], Optional[str]]:
    """Return ``(recovery_point_id, backup_vault_name)`` for backup events."""
    params = record.get("requestParameters") if isinstance(record.get("requestParameters"), dict) else {}
    vault = params.get("backupVaultName") or params.get("BackupVaultName")
    rp_id: Optional[str] = None
    rp_arn = params.get("recoveryPointArn") or params.get("RecoveryPointArn")
    if isinstance(rp_arn, str) and rp_arn.startswith("arn:"):
        rp_id = _resource_id_from_arn(rp_arn)
    if rp_id is None:
        for resource in _extract_resources(record):
            arn = resource.get("ARN") or resource.get("arn")
            if isinstance(arn, str) and "recovery-point" in arn:
                rp_id = _resource_id_from_arn(arn)
                break
    if rp_id:
        tracker.available("recovery_point_id")
    else:
        tracker.unavailable("recovery_point_id", UnavailableReason.NOT_IN_SOURCE)
    if isinstance(vault, str) and vault.strip():
        tracker.available("backup_vault_name")
        return rp_id, vault.strip()
    tracker.unavailable("backup_vault_name", UnavailableReason.NOT_IN_SOURCE)
    return rp_id, None


def _extract_object_count(record: dict[str, Any], tracker: AvailabilityTracker) -> Optional[int]:
    """Count objects for batch operations (e.g. ``DeleteObjects``)."""
    params = record.get("requestParameters") if isinstance(record.get("requestParameters"), dict) else {}
    objects: Any = params.get("objects")
    delete_request = params.get("Delete") or params.get("DeleteObjectsRequest")
    if objects is None and isinstance(delete_request, dict):
        objects = delete_request.get("Objects") or delete_request.get("objects")
    if isinstance(objects, list) and objects:
        tracker.available("object_count", derived=True)
        return len(objects)
    tracker.unavailable("object_count", UnavailableReason.NOT_IN_SOURCE)
    return None


# --------------------------------------------------------------------------- #
# Protection-state enrichment
# --------------------------------------------------------------------------- #

_PROTECTION_FIELDS = (
    "business_criticality",
    "sensitivity_level",
    "versioning_enabled",
    "object_lock_enabled",
    "backup_enabled",
    "snapshot_protection_enabled",
    "retention_period",
)


def _apply_protection_enrichment(
    catalog: Optional[ProtectionCatalog],
    resource_id: Optional[str],
    resource_arn: Optional[str],
    tracker: AvailabilityTracker,
) -> dict[str, Any]:
    """Overlay catalog facts onto the event; record availability per field."""
    enriched: dict[str, Any] = {}
    state: Optional[ProtectionState] = None
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
            # Unknown label: keep None rather than coercing to a wrong level.
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


# --------------------------------------------------------------------------- #
# Normalizer
# --------------------------------------------------------------------------- #


class ResourceActivityNormalizer:
    """Converts provider telemetry into canonical :class:`ResourceActivityEvent`."""

    def __init__(self, catalog: Optional[ProtectionCatalog] = None) -> None:
        self._catalog = catalog

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def normalize(
        self,
        provider: CloudProvider,
        record: dict[str, Any],
        *,
        raw_event_reference: Optional[str] = None,
    ) -> ResourceActivityEvent:
        """Normalize one record with the normalizer registered for *provider*."""
        if provider is CloudProvider.AWS:
            return self.normalize_cloudtrail(record, raw_event_reference=raw_event_reference)
        raise UnsupportedEventError(
            f"no normalizer registered for provider {provider.value}"
        )

    def normalize_generic(
        self,
        record: dict[str, Any],
        *,
        is_synthetic: bool = False,
        generator: Optional[str] = None,
    ) -> ResourceActivityEvent:
        """Normalize an already-canonical record (fixtures / other clouds).

        The caller asserts canonical field values; the normalizer validates
        them and records provenance as synthetic/canonical input.
        """
        if not isinstance(record, dict):
            raise MalformedEventError("generic record must be a dict", raw_event=record)
        tracker = AvailabilityTracker()
        for field_name in (
            "event_id",
            "timestamp",
            "actor_id",
            "resource_id",
            "action_category",
        ):
            if record.get(field_name) is not None:
                tracker.available(field_name)
            else:
                tracker.unavailable(field_name, UnavailableReason.NOT_IN_SOURCE)
        try:
            return ResourceActivityEvent(
                event_id=str(record["event_id"]),
                timestamp=_parse_timestamp(record.get("timestamp")),
                provider=CloudProvider(str(record.get("provider") or CloudProvider.AWS.value)),
                account_id=record.get("account_id"),
                region=record.get("region"),
                actor_id=record.get("actor_id"),
                actor_type=ActorType(str(record.get("actor_type") or ActorType.UNKNOWN.value)),
                session_id=record.get("session_id"),
                resource_id=record.get("resource_id"),
                resource_type=ResourceType(str(record.get("resource_type") or ResourceType.UNKNOWN.value)),
                resource_arn=record.get("resource_arn"),
                action_category=ActionCategory(str(record.get("action_category") or ActionCategory.UNKNOWN.value)),
                raw_action=record.get("raw_action"),
                object_key=record.get("object_key"),
                version_id=record.get("version_id"),
                is_delete_marker=bool(record.get("is_delete_marker", False)),
                snapshot_id=record.get("snapshot_id"),
                recovery_point_id=record.get("recovery_point_id"),
                backup_vault_name=record.get("backup_vault_name"),
                object_count=record.get("object_count"),
                bytes_changed=record.get("bytes_changed"),
                source_ip=record.get("source_ip"),
                user_agent=record.get("user_agent"),
                business_criticality=(
                    BusinessCriticality(record["business_criticality"])
                    if record.get("business_criticality")
                    else None
                ),
                sensitivity_level=None,
                versioning_enabled=record.get("versioning_enabled"),
                object_lock_enabled=record.get("object_lock_enabled"),
                backup_enabled=record.get("backup_enabled"),
                snapshot_protection_enabled=record.get("snapshot_protection_enabled"),
                retention_period=record.get("retention_period"),
                request_parameters=record.get("request_parameters"),
                raw_event_reference=record.get("raw_event_reference"),
                feature_availability=tracker.to_tuple(),
                data_provenance=DataProvenance(
                    source_type="synthetic" if is_synthetic else "canonical",
                    ingestion_pipeline="detection.cloud_destruction.normalizer.normalize_generic",
                    is_synthetic=is_synthetic,
                    generator=generator,
                ),
            )
        except KeyError as exc:
            raise MalformedEventError(
                f"generic record missing required field {exc}", raw_event=record, cause=exc
            ) from exc
        except Exception as exc:
            raise MalformedEventError(
                f"generic normalization failed: {exc}", raw_event=record, cause=exc
            ) from exc

    # ------------------------------------------------------------------
    # AWS CloudTrail
    # ------------------------------------------------------------------

    def normalize_cloudtrail(
        self,
        record: dict[str, Any],
        raw_event_reference: Optional[str] = None,
        *,
        raw_record_index: Optional[int] = None,
        is_replayed: bool = False,
        is_synthetic: bool = False,
        generator: Optional[str] = None,
    ) -> ResourceActivityEvent:
        """Normalize one AWS CloudTrail record into a canonical event.

        Raises :class:`UnsupportedEventError` for structurally valid records
        that are out of scope (e.g. console sign-ins, read-only listing).
        """
        if not isinstance(record, dict):
            raise MalformedEventError("CloudTrail record must be a dict", raw_event=record)

        version = record.get("eventVersion")
        if version is not None and not (isinstance(version, str) and version.startswith("1.")):
            raise MalformedEventError(
                f"unsupported CloudTrail eventVersion {version!r}",
                missing_fields=["eventVersion"],
                raw_event=record,
            )

        event_id = record.get("eventID") or record.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            raise MalformedEventError(
                "CloudTrail record missing eventID", missing_fields=["eventID"], raw_event=record
            )
        timestamp = _extract_timestamp(record)

        event_name = record.get("eventName")
        event_source = record.get("eventSource")
        if not isinstance(event_name, str) or not event_name.strip():
            raise MalformedEventError(
                "CloudTrail record missing eventName", missing_fields=["eventName"], raw_event=record
            )
        source_ns = str(event_source or "").strip().lower().removesuffix(".amazonaws.com")
        mapped = classify_action(source_ns, event_name)
        if mapped is None:
            raise UnsupportedEventError(
                f"not a resource-destructive-scope event: {source_ns}.{event_name}",
                context={"event_id": event_id},
            )
        category, operation, implied_type = mapped

        tracker = AvailabilityTracker()
        tracker.available("event_id")
        tracker.available("timestamp")
        tracker.available("action_category")
        tracker.available("resource_type", derived=True)

        actor_id, actor_type, session_id = _extract_actor(record, tracker)

        account_id = record.get("recipientAccountId") or record.get("awsAccountId")
        if isinstance(account_id, str) and account_id.strip():
            tracker.available("account_id")
        else:
            account_id = None
            tracker.unavailable("account_id", UnavailableReason.NOT_IN_SOURCE)

        region = record.get("awsRegion")
        if isinstance(region, str) and region.strip():
            tracker.available("region")
        else:
            region = None
            tracker.unavailable("region", UnavailableReason.NOT_IN_SOURCE)

        params: dict[str, Any] = (
            record.get("requestParameters")
            if isinstance(record.get("requestParameters"), dict)
            else {}
        )

        # --- resource extraction depends on the service ------------------------
        if source_ns == "s3":
            resource_id, resource_arn, object_key = _extract_s3_target(record, tracker)
            resource_type = implied_type
        else:
            resource_id, resource_arn, resource_type = _extract_arn_target(record, tracker)
            object_key = None

        version_id: Optional[str] = None
        is_delete_marker = False
        if source_ns == "s3":
            raw_version = params.get("versionId")
            if isinstance(raw_version, str) and raw_version.strip():
                version_id = raw_version.strip()
                tracker.available("version_id")
                if category is ActionCategory.DELETE:
                    category = ActionCategory.VERSION_DELETE
                    operation = OperationType.VERSIONED
            else:
                tracker.unavailable("version_id", UnavailableReason.NOT_IN_SOURCE)
            delete_marker = (record.get("responseElements") or {}).get("x-amz-delete-marker")
            if str(delete_marker).lower() == "true":
                is_delete_marker = True
                operation = OperationType.DELETE_MARKER
                tracker.available("is_delete_marker", derived=True)
            else:
                tracker.unavailable("is_delete_marker", UnavailableReason.NOT_IN_SOURCE)
        else:
            tracker.unavailable("version_id", UnavailableReason.FIELD_NOT_APPLICABLE)
            tracker.unavailable("is_delete_marker", UnavailableReason.FIELD_NOT_APPLICABLE)

        snapshot_id = None
        recovery_point_id = None
        backup_vault_name = None
        if category is ActionCategory.SNAPSHOT_DELETE or (
            source_ns in {"ec2", "rds"} and "snapshot" in event_name.lower()
        ):
            snapshot_id = _extract_snapshot_id(record, tracker)
        elif source_ns == "backup":
            recovery_point_id, backup_vault_name = _extract_recovery_point(record, tracker)
        else:
            tracker.unavailable("snapshot_id", UnavailableReason.FIELD_NOT_APPLICABLE)
            tracker.unavailable("recovery_point_id", UnavailableReason.FIELD_NOT_APPLICABLE)
            tracker.unavailable("backup_vault_name", UnavailableReason.FIELD_NOT_APPLICABLE)

        object_count = _extract_object_count(record, tracker)
        if category in {ActionCategory.DELETE, ActionCategory.VERSION_DELETE} and object_count is None:
            object_count = 1
            tracker.available("object_count", derived=True)
        tracker.unavailable("bytes_changed", UnavailableReason.NOT_IN_SOURCE)

        source_ip = record.get("sourceIPAddress")
        if isinstance(source_ip, str) and source_ip.strip():
            # AWS internal pseudo-IPs are kept verbatim as evidence; parsing
            # into a normalized form is intentionally avoided (never invent).
            tracker.available("source_ip")
        else:
            source_ip = None
            tracker.unavailable("source_ip", UnavailableReason.NOT_IN_SOURCE)
        tls = record.get("tlsDetails")
        user_agent = record.get("userAgent") or (
            tls.get("tlsVersion") if isinstance(tls, dict) else None
        )
        if isinstance(user_agent, str) and user_agent.strip():
            tracker.available("user_agent")
        else:
            user_agent = None
            tracker.unavailable("user_agent", UnavailableReason.NOT_IN_SOURCE)

        enriched = _apply_protection_enrichment(
            self._catalog, resource_id, resource_arn, tracker
        )

        provenance = DataProvenance(
            source_type="cloudtrail",
            ingestion_pipeline="aws.cloudtrail_resource_activity",
            raw_record_index=raw_record_index,
            raw_reference=raw_event_reference,
            is_replayed=is_replayed,
            is_synthetic=is_synthetic,
            generator=generator,
            normalizer_version=NORMALIZER_VERSION,
        )

        event = ResourceActivityEvent(
            event_id=event_id.strip(),
            timestamp=timestamp,
            provider=CloudProvider.AWS,
            account_id=account_id,
            region=region,
            actor_id=actor_id,
            actor_type=actor_type,
            session_id=session_id,
            resource_id=resource_id,
            resource_type=resource_type,
            resource_arn=resource_arn,
            action=category.value,
            action_category=category,
            operation_type=operation,
            raw_action=f"{source_ns}:{event_name}",
            object_key=object_key,
            version_id=version_id,
            is_delete_marker=is_delete_marker,
            snapshot_id=snapshot_id,
            recovery_point_id=recovery_point_id,
            backup_vault_name=backup_vault_name,
            object_count=object_count,
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
            request_parameters=params or None,
            raw_event_reference=raw_event_reference,
            feature_availability=tracker.to_tuple(),
            data_provenance=provenance,
        )
        return event


__all__ = [
    "ResourceActivityNormalizer",
    "classify_action",
]
