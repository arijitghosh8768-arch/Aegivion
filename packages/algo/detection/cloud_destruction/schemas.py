"""Provider-neutral domain schemas for the Cloud Destructive Activity Detector.

Design rules enforced here (mirroring Algorithms #1/#2):

1. **Nothing is invented.** If a telemetry source does not provide a value the
   field stays ``None`` and the per-field availability record explains why
   (see :mod:`detection.cloud_destruction.provenance`).
2. **Every canonical event is self-describing**: it carries
   ``feature_availability`` and ``data_provenance``.
3. Provider-specific raw actions (e.g. ``DeleteObjectVersion``) are always kept
   as evidence in ``raw_action`` next to the canonical taxonomy value.
4. Sensitivity / business criticality / protection flags are external facts
   (catalog or enrichment). When no catalog entry exists they stay ``None`` —
   the detector never guesses how important a resource is.
5. Part 1 computes **no destruction score and no ransomware verdict**; those
   stages raise :class:`NotImplementedYetError` until their part lands.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from algo.detection.cloud_destruction.exceptions import MalformedEventError
from algo.detection.cloud_destruction.provenance import (
    DataProvenance,
    FieldAvailability,
)


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #


def utcnow() -> datetime:
    """Timezone-aware "now" in UTC."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Coerce a datetime to timezone-aware UTC.

    Naive timestamps are assumed UTC; AWS always emits UTC.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class CloudProvider(str, enum.Enum):
    """Cloud providers. AWS ships first; Azure/GCP are schema-reserved."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    UNKNOWN = "unknown"


class ActorType(str, enum.Enum):
    """Coarse kind of the acting principal (CloudTrail ``userIdentity.type``)."""

    IAM_USER = "iam_user"
    ASSUMED_ROLE = "assumed_role"
    ROOT = "root"
    FEDERATED_USER = "federated_user"
    AWS_SERVICE = "aws_service"
    SERVICE_ACCOUNT = "service_account"
    UNKNOWN = "unknown"


class ActionCategory(str, enum.Enum):
    """Canonical action taxonomy for destructive-activity detection.

    Provider raw actions are preserved separately as evidence, so this
    taxonomy can stay small and stable.
    """

    CREATE = "create"
    READ = "read"
    MODIFY = "modify"
    REWRITE = "rewrite"
    DELETE = "delete"
    VERSION_DELETE = "version_delete"
    SNAPSHOT_DELETE = "snapshot_delete"
    BACKUP_DELETE = "backup_delete"
    RECOVERY_POINT_DELETE = "recovery_point_delete"
    PROTECTION_CHANGE = "protection_change"
    RESTORE = "restore"
    SHARE_CHANGE = "share_change"
    POLICY_CHANGE = "policy_change"
    UNKNOWN = "unknown"


#: Categories that consume or degrade recovery/protection state.
DESTRUCTIVE_CATEGORIES: frozenset[ActionCategory] = frozenset(
    {
        ActionCategory.DELETE,
        ActionCategory.VERSION_DELETE,
        ActionCategory.SNAPSHOT_DELETE,
        ActionCategory.BACKUP_DELETE,
        ActionCategory.RECOVERY_POINT_DELETE,
        ActionCategory.PROTECTION_CHANGE,
        ActionCategory.MODIFY,
        ActionCategory.REWRITE,
    }
)


class OperationType(str, enum.Enum):
    """Destructive-scope nuance on top of :class:`ActionCategory`."""

    SINGLE = "single"
    BATCH = "batch"
    VERSIONED = "versioned"
    DELETE_MARKER = "delete_marker"
    RECOVERY_IMPAIRING = "recovery_impairing"
    UNKNOWN = "unknown"


class BusinessCriticality(str, enum.Enum):
    """Business importance supplied by the resource catalog (never guessed)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCLASSIFIED = "unclassified"


class SensitivityLevel(str, enum.Enum):
    """Data-sensitivity classification supplied by external enrichment."""

    NONE = "none"
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    CRITICAL = "critical"
    PII = "pii"
    PHI = "phi"
    FINANCIAL = "financial"
    SECRETS = "secrets"


class ResourceType(str, enum.Enum):
    """Canonical resource types. Strings are stable wire values."""

    S3_BUCKET = "s3_bucket"
    S3_OBJECT = "s3_object"
    EBS_VOLUME = "ebs_volume"
    EBS_SNAPSHOT = "ebs_snapshot"
    RDS_INSTANCE = "rds_instance"
    RDS_SNAPSHOT = "rds_snapshot"
    BACKUP_VAULT = "backup_vault"
    RECOVERY_POINT = "recovery_point"
    EC2_INSTANCE = "ec2_instance"
    LAMBDA_FUNCTION = "lambda_function"
    DYNAMODB_TABLE = "dynamodb_table"
    EFS_FILESYSTEM = "efs_filesystem"
    UNKNOWN = "unknown"


#: Action categories that reduce recoverability when performed.
RECOVERY_IMPAIRING_CATEGORIES: frozenset[ActionCategory] = frozenset(
    {
        ActionCategory.SNAPSHOT_DELETE,
        ActionCategory.BACKUP_DELETE,
        ActionCategory.RECOVERY_POINT_DELETE,
        ActionCategory.PROTECTION_CHANGE,
    }
)


def map_resource_type(arn_or_type: Optional[str]) -> ResourceType:
    """Best-effort mapping of an ARN / service string to a canonical type.

    Returns ``ResourceType.UNKNOWN`` when unmapped; never raises and never
    invents a more specific type than the evidence supports.
    """
    if not arn_or_type:
        return ResourceType.UNKNOWN
    text = arn_or_type.lower()
    if text.startswith("arn:aws:s3:::"):
        # bucket ARNs carry no path (``arn:aws:s3:::my-bucket``); anything with
        # a trailing path segment is an object within the bucket.
        tail = arn_or_type.split(":::", 1)[1]
        return ResourceType.S3_OBJECT if "/" in tail else ResourceType.S3_BUCKET
    if "s3" in text:
        return ResourceType.S3_BUCKET
    if "ebs" in text or ":volume/" in text:
        return ResourceType.EBS_VOLUME
    if "snapshot" in text:
        if "rds" in text:
            return ResourceType.RDS_SNAPSHOT
        return ResourceType.EBS_SNAPSHOT
    if "rds" in text and ":db:" in text:
        return ResourceType.RDS_INSTANCE
    if "recovery-point" in text or "recovery_point" in text:
        return ResourceType.RECOVERY_POINT
    if "backup" in text and "vault" in text:
        return ResourceType.BACKUP_VAULT
    if ":instance/" in text and "ec2" in text:
        return ResourceType.EC2_INSTANCE
    if ":function:" in text:
        return ResourceType.LAMBDA_FUNCTION
    if "dynamodb" in text:
        return ResourceType.DYNAMODB_TABLE
    if "elasticfilesystem" in text or ":file-system/" in text:
        return ResourceType.EFS_FILESYSTEM
    return ResourceType.UNKNOWN


# --------------------------------------------------------------------------- #
# Canonical event
# --------------------------------------------------------------------------- #


class ResourceActivityEvent(BaseModel):
    """Canonical, provider-neutral record of one resource-affecting action.

    This is the contract between ingestion and the detection algorithm. Every
    field a source did not provide stays ``None`` and is mirrored in
    ``feature_availability`` with the reason it is unavailable.
    """

    model_config = ConfigDict(extra="forbid")

    # --- event identity -----------------------------------------------------
    event_id: str
    timestamp: datetime
    provider: CloudProvider = CloudProvider.AWS
    account_id: Optional[str] = None
    region: Optional[str] = None

    # --- actor ---------------------------------------------------------------
    actor_id: Optional[str] = None
    actor_type: ActorType = ActorType.UNKNOWN
    session_id: Optional[str] = None

    # --- resource -------------------------------------------------------------
    resource_id: Optional[str] = None
    resource_type: ResourceType = ResourceType.UNKNOWN
    resource_arn: Optional[str] = None

    # --- action ----------------------------------------------------------------
    action: str = "unknown"
    """Canonical action name (an :class:`ActionCategory` value)."""
    action_category: ActionCategory = ActionCategory.UNKNOWN
    operation_type: OperationType = OperationType.UNKNOWN
    raw_action: Optional[str] = None
    """Provider-specific action, preserved as evidence (never normalized away)."""

    # --- object / version / recovery identifiers ---------------------------------
    object_key: Optional[str] = None
    version_id: Optional[str] = None
    is_delete_marker: bool = False
    snapshot_id: Optional[str] = None
    recovery_point_id: Optional[str] = None
    backup_vault_name: Optional[str] = None

    # --- quantitative -------------------------------------------------------------
    object_count: Optional[int] = None
    bytes_changed: Optional[int] = None

    # --- network / client ------------------------------------------------------------
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None

    # --- external enrichment (never guessed) -------------------------------------------
    business_criticality: Optional[BusinessCriticality] = None
    sensitivity_level: Optional[SensitivityLevel] = None

    # --- protection state observed at event time -----------------------------------------
    versioning_enabled: Optional[bool] = None
    object_lock_enabled: Optional[bool] = None
    backup_enabled: Optional[bool] = None
    snapshot_protection_enabled: Optional[bool] = None
    retention_period: Optional[int] = None
    """Retention in days when the source states one; otherwise ``None``."""

    # --- evidence ---------------------------------------------------------------------
    request_parameters: Optional[dict[str, Any]] = None
    raw_event_reference: Optional[str] = None

    # --- self-description -----------------------------------------------------------------
    feature_availability: tuple[FieldAvailability, ...] = ()
    data_provenance: Optional[DataProvenance] = None

    # ------------------------------------------------------------------ #
    # Validation
    # ------------------------------------------------------------------ #

    @field_validator("timestamp", mode="after")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("event_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if value is None or not str(value).strip():
            raise MalformedEventError(
                "event_id must be a non-empty string", missing_fields=["event_id"]
            )
        return value

    @model_validator(mode="after")
    def _validate_consistency(self) -> "ResourceActivityEvent":
        # action must be a taxonomy value when it is not the default
        if self.action != "unknown" and self.action not in {c.value for c in ActionCategory}:
            raise MalformedEventError(
                "action must be a canonical ActionCategory value",
                context={"action": self.action},
            )
        if self.action_category is not ActionCategory.UNKNOWN and self.action == "unknown":
            self.action = self.action_category.value
        if self.object_count is not None and self.object_count < 0:
            raise MalformedEventError("object_count cannot be negative")
        if self.bytes_changed is not None and self.bytes_changed < 0:
            raise MalformedEventError("bytes_changed cannot be negative")
        if self.retention_period is not None and self.retention_period < 0:
            raise MalformedEventError("retention_period cannot be negative")
        return self

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @property
    def is_destructive(self) -> bool:
        return self.action_category in DESTRUCTIVE_CATEGORIES

    @property
    def is_recovery_impairing(self) -> bool:
        return self.action_category in RECOVERY_IMPAIRING_CATEGORIES

    def availability_map(self) -> dict[str, FieldAvailability]:
        return {item.field: item for item in self.feature_availability}

    def to_log_dict(self) -> dict[str, Any]:
        """Redacted, log-safe view (never dumps raw request parameters)."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "provider": self.provider.value,
            "account_id": self.account_id,
            "region": self.region,
            "actor_id": self.actor_id,
            "actor_type": self.actor_type.value,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type.value,
            "action": self.action,
            "action_category": self.action_category.value,
            "operation_type": self.operation_type.value,
            "object_key": self.object_key,
            "version_id": self.version_id,
            "is_delete_marker": self.is_delete_marker,
            "snapshot_id": self.snapshot_id,
            "recovery_point_id": self.recovery_point_id,
            "object_count": self.object_count,
            "bytes_changed": self.bytes_changed,
            "source_ip": self.source_ip,
            "warnings": [a.field for a in self.feature_availability if not a.is_available],
        }


# --------------------------------------------------------------------------- #
# Resource protection profile
# --------------------------------------------------------------------------- #


class ResourceProtectionProfile(BaseModel):
    """"What normal looks like" for one resource + its recovery posture.

    Rates are descriptive history (events/day), populated by
    :mod:`detection.cloud_destruction.baseline` (Part 2). Part 1 only records
    catalog facts and observed history counts. ``recoverability_score`` is
    always ``None`` in Part 1 — computing it is a later part's job.
    """

    model_config = ConfigDict(extra="forbid")

    resource_id: str
    resource_type: ResourceType = ResourceType.UNKNOWN
    resource_arn: Optional[str] = None
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    business_criticality: Optional[BusinessCriticality] = None

    # baseline rates (per day) — Part 2 fills these from history
    normal_write_rate: Optional[float] = None
    normal_modify_rate: Optional[float] = None
    normal_delete_rate: Optional[float] = None
    normal_rewrite_rate: Optional[float] = None

    normal_actor_set: tuple[str, ...] = Field(default_factory=tuple)
    normal_change_windows: tuple[str, ...] = Field(default_factory=tuple)
    """Named windows (e.g. ``"lifecycle-02:00-03:00"``) from observed history."""

    # protection posture (catalog facts)
    versioning_enabled: Optional[bool] = None
    object_lock_enabled: Optional[bool] = None
    backup_enabled: Optional[bool] = None
    snapshot_enabled: Optional[bool] = None
    snapshot_protection_enabled: Optional[bool] = None
    recovery_point_available: Optional[bool] = None
    retention_configuration: Optional[dict[str, Any]] = None

    # observed history counters
    observed_write_events: int = 0
    observed_modify_events: int = 0
    observed_delete_events: int = 0
    observed_rewrite_events: int = 0
    history_event_count: int = 0
    observation_start: Optional[datetime] = None
    observation_end: Optional[datetime] = None

    # Part 1 leaves this unset: scoring belongs to a later part.
    recoverability_score: Optional[float] = None

    @field_validator("observation_start", "observation_end", mode="after")
    @classmethod
    def _to_utc(cls, value: Optional[datetime]) -> Optional[datetime]:
        return ensure_utc(value) if value is not None else None

    @property
    def has_protection(self) -> bool:
        """True only when at least one recovery mechanism is known to be on."""
        return bool(
            self.backup_enabled
            or self.snapshot_enabled
            or self.recovery_point_available
            or (self.versioning_enabled and self.object_lock_enabled)
        )


# --------------------------------------------------------------------------- #
# Destructive session
# --------------------------------------------------------------------------- #


class DestructiveActivitySession(BaseModel):
    """Per-actor burst of related resource activity.

    Aggregates are sums of per-event observations, not estimates. Every
    counter starts at zero; nothing is inferred beyond what contributing
    events explicitly show. ``risk_state`` never leaves ``new``/``analyzed``
    in Part 1 — flagging arrives with Part 2+.
    """

    model_config = ConfigDict(extra="forbid")

    session_id: str
    actor_id: Optional[str] = None
    provider: CloudProvider = CloudProvider.AWS
    account_id: Optional[str] = None

    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    event_count: int = 0
    destructive_event_count: int = 0

    modified_resources: list[str] = Field(default_factory=list)
    deleted_resources: list[str] = Field(default_factory=list)
    rewrite_count: int = 0
    version_deletions: int = 0
    delete_marker_count: int = 0
    snapshot_deletions: int = 0
    backup_deletions: int = 0
    protection_changes: int = 0
    restore_count: int = 0

    unique_resource_count: int = 0
    unique_resource_types: int = 0

    critical_resource_touched: bool = False
    """True when any contributing event hit a criticality=critical resource."""

    event_ids: list[str] = Field(default_factory=list)
    resources_touched: list[str] = Field(default_factory=list)

    risk_state: str = "new"
    """Part 1 lifecycle only: ``new`` -> ``analyzed``."""

    @field_validator("start_time", "end_time", mode="after")
    @classmethod
    def _to_utc(cls, value: Optional[datetime]) -> Optional[datetime]:
        return ensure_utc(value) if value is not None else None

    @property
    def duration_seconds(self) -> float:
        if self.start_time is None or self.end_time is None:
            return 0.0
        return max(0.0, (self.end_time - self.start_time).total_seconds())

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"DestructiveActivitySession(session_id={self.session_id!r}, "
            f"actor={self.actor_id!r}, events={self.event_count}, "
            f"destructive={self.destructive_event_count})"
        )


__all__ = [
    "ActionCategory",
    "ActorType",
    "BusinessCriticality",
    "CloudProvider",
    "DESTRUCTIVE_CATEGORIES",
    "DestructiveActivitySession",
    "OperationType",
    "RECOVERY_IMPAIRING_CATEGORIES",
    "ResourceActivityEvent",
    "ResourceProtectionProfile",
    "ResourceType",
    "SensitivityLevel",
    "ensure_utc",
    "map_resource_type",
    "utcnow",
]
