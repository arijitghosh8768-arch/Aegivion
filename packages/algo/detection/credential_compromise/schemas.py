"""Provider-neutral domain schemas for the Cloud Credential Compromise detector.

Everything downstream of the normalizer speaks this vocabulary, so adding Azure
or GCP later means writing a new normalizer - not rewriting the algorithm.

Security note: :class:`IdentityActivityEvent` never exposes access key material.
``__repr__`` and :meth:`IdentityActivityEvent.to_log_dict` redact it, and only a
salted fingerprint of the key ID is ever persisted.
"""

from __future__ import annotations

import enum
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def utcnow() -> datetime:
    """Timezone-aware "now" in UTC."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Coerce a datetime to timezone-aware UTC.

    Naive timestamps are assumed to be UTC; provider payloads are expected to
    carry ``Z``/offset timestamps and AWS always emits UTC.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def normalize_ip(value: Optional[str]) -> Optional[str]:
    """Return a canonical IP string, or ``None`` for empty input.

    Raises ``ValueError`` for anything that is not a valid IP address. Callers
    that must tolerate AWS pseudo-sources (e.g. ``AWS Internal``) catch this and
    record a parse warning instead of guessing.
    """
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    # Some services append a port, e.g. "1.2.3.4:443".
    if candidate.count(":") == 1 and "." in candidate:
        host, _, port = candidate.partition(":")
        if port.isdigit():
            candidate = host
    return str(ipaddress.ip_address(candidate))


def mask_secret(
    value: Optional[str], *, keep_start: int = 4, keep_end: int = 5
) -> Optional[str]:
    """Return a non-reversible-looking display form such as ``"AKIA********EVKEY"``.

    Preserves ``keep_start`` leading and ``keep_end`` trailing characters and
    replaces everything in between with asterisks; the mask length is always
    derived from the input length. Values too short to safely reveal both ends
    are fully masked.
    """
    if not value:
        return None
    keep_start = max(0, keep_start)
    keep_end = max(0, keep_end)
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    mask_len = len(value) - keep_start - keep_end
    tail = value[-keep_end:] if keep_end else ""
    return f"{value[:keep_start]}{'*' * mask_len}{tail}"


def fingerprint_secret(value: Optional[str], *, salt: str = "") -> Optional[str]:
    """Salted SHA-256 of a credential identifier.

    Used so behavioural novelty checks can compare access keys without ever
    persisting key material.
    """
    if not value:
        return None
    digest = hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()
    return digest


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class CloudProvider(str, enum.Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    UNKNOWN = "unknown"


class PrincipalType(str, enum.Enum):
    """CloudTrail ``userIdentity.type`` values plus explicit unknowns."""

    IAM_USER = "IAMUser"
    ASSUMED_ROLE = "AssumedRole"
    ROOT = "Root"
    FEDERATED_USER = "FederatedUser"
    AWS_SERVICE = "AWSService"
    SERVICE_ACCOUNT = "ServiceAccount"
    UNKNOWN = "Unknown"


class IdentityKind(str, enum.Enum):
    """Coarse nature of the acting identity."""

    HUMAN = "human"
    MACHINE = "machine"
    SERVICE = "service"
    FEDERATED = "federated"
    UNKNOWN = "unknown"


class BaselineCategory(str, enum.Enum):
    """Baselines are kept per category so humans are never compared to machines."""

    HUMAN_USER = "human_user"
    ASSUMED_ROLE = "assumed_role"
    FEDERATED_IDENTITY = "federated_identity"
    SERVICE_IDENTITY = "service_identity"
    MACHINE_IDENTITY = "machine_identity"
    UNKNOWN = "unknown"


class EventCategory(str, enum.Enum):
    MANAGEMENT = "management"
    DATA = "data"
    INSIGHT = "insight"
    SIGNIN = "signin"
    UNKNOWN = "unknown"


class AccessType(str, enum.Enum):
    READ = "read"
    WRITE = "write"
    UNKNOWN = "unknown"


class BaselineQuality(str, enum.Enum):
    """How much trust the detector places in a baseline. Feeds confidence."""

    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    LIMITED = "LIMITED"
    COLD_START = "COLD_START"


class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApiFamilies:
    """Canonical API family constants.

    Kept as plain strings (not an enum) so provider-specific families can be
    added without breaking stored data.
    """

    CONSOLE_SIGNIN = "CONSOLE_SIGNIN"
    SSO = "SSO"
    STS_SESSION = "STS_SESSION"
    CREDENTIAL_MANAGEMENT = "CREDENTIAL_MANAGEMENT"
    IAM_PRIVILEGE_MUTATION = "IAM_PRIVILEGE_MUTATION"
    IAM_USER_MANAGEMENT = "IAM_USER_MANAGEMENT"
    IAM_READ = "IAM_READ"
    S3_DATA_READ = "S3_DATA_READ"
    S3_DATA_WRITE = "S3_DATA_WRITE"
    S3_MANAGEMENT = "S3_MANAGEMENT"
    EC2_MANAGEMENT = "EC2_MANAGEMENT"
    EC2_READ = "EC2_READ"
    LAMBDA_MANAGEMENT = "LAMBDA_MANAGEMENT"
    EKS_MANAGEMENT = "EKS_MANAGEMENT"
    RDS_MANAGEMENT = "RDS_MANAGEMENT"
    SECRETS_ACCESS = "SECRETS_ACCESS"
    SECRETS_MANAGEMENT = "SECRETS_MANAGEMENT"
    KMS_CRYPTO = "KMS_CRYPTO"
    KMS_MANAGEMENT = "KMS_MANAGEMENT"
    CLOUDTRAIL_TAMPER = "CLOUDTRAIL_TAMPER"
    GUARDDUTY_TAMPER = "GUARDDUTY_TAMPER"
    CONFIG_TAMPER = "CONFIG_TAMPER"
    ORGANIZATIONS_MANAGEMENT = "ORGANIZATIONS_MANAGEMENT"
    DEFAULT = "DEFAULT_API"


#: Families whose use constitutes a privilege or credential change.
PRIVILEGE_MUTATION_FAMILIES: frozenset[str] = frozenset(
    {
        ApiFamilies.IAM_PRIVILEGE_MUTATION,
        ApiFamilies.CREDENTIAL_MANAGEMENT,
    }
)


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #


class ResolvedIdentity(BaseModel):
    """Stable identity handle produced by the identity resolver."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    identity_key: str
    provider: CloudProvider
    account_id: Optional[str] = None
    principal_id: str
    principal_name: Optional[str] = None
    principal_type: PrincipalType
    identity_kind: IdentityKind
    baseline_category: BaselineCategory
    role_arn: Optional[str] = None
    session_id: Optional[str] = None
    is_human_session: bool = False
    raw_type: Optional[str] = None
    department: Optional[str] = None
    team: Optional[str] = None

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"ResolvedIdentity(identity_key={self.identity_key!r}, principal_name={self.principal_name!r})"


class IpIntelligence(BaseModel):
    """Enrichment attached to a source IP. ``None`` means "unknown"."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    country: Optional[str] = None
    region_hint: Optional[str] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_known_proxy: bool = False

    @property
    def is_empty(self) -> bool:
        return not any(
            (self.country, self.region_hint, self.asn, self.asn_org)
        ) and not self.is_known_proxy


# --------------------------------------------------------------------------- #
# Core event
# --------------------------------------------------------------------------- #


class IdentityActivityEvent(BaseModel):
    """Canonical, provider-neutral identity activity event.

    This is the contract between ingestion and the detection algorithm.
    """

    model_config = ConfigDict(extra="forbid")

    # --- Identity of the event itself -------------------------------------
    event_id: str
    timestamp: datetime
    ingest_time: datetime = Field(default_factory=utcnow)
    provider: CloudProvider = CloudProvider.AWS
    account_id: Optional[str] = None

    # --- Where ------------------------------------------------------------
    region: Optional[str] = None          # cloud region, e.g. ap-south-1
    region_hint: Optional[str] = None     # geographic hint, e.g. Maharashtra

    # --- Who --------------------------------------------------------------
    principal_id: str
    principal_name: Optional[str] = None
    principal_type: PrincipalType
    identity_kind: IdentityKind = IdentityKind.UNKNOWN
    baseline_category: BaselineCategory = BaselineCategory.UNKNOWN
    identity_key: Optional[str] = None
    access_key_id: Optional[str] = None
    role_arn: Optional[str] = None
    session_id: Optional[str] = None
    session_creation_time: Optional[datetime] = None
    is_human_session: bool = False

    # --- What -------------------------------------------------------------
    event_source: str
    event_name: str
    event_category: EventCategory = EventCategory.UNKNOWN
    service_name: str
    api_family: str = ApiFamilies.DEFAULT
    read_or_write: AccessType = AccessType.UNKNOWN
    privilege_change: bool = False

    # --- Network / client -------------------------------------------------
    source_ip: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None
    user_agent: Optional[str] = None
    mfa_authenticated: Optional[bool] = None

    # --- Context ----------------------------------------------------------
    request_rate_context: Optional[float] = None
    raw_event_reference: Optional[str] = None
    normalization_warnings: tuple[str, ...] = ()

    # ------------------------------------------------------------------ #
    # Validation
    # ------------------------------------------------------------------ #

    @field_validator("timestamp", "ingest_time", "session_creation_time", mode="after")
    @classmethod
    def _to_utc(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        return ensure_utc(value)

    @field_validator("source_ip", mode="after")
    @classmethod
    def _validate_ip(cls, value: Optional[str]) -> Optional[str]:
        return normalize_ip(value)

    @field_validator("event_id", "event_source", "event_name", "service_name", "principal_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if value is None or not str(value).strip():
            raise ValueError("must be a non-empty string")
        return value

    # ------------------------------------------------------------------ #
    # Safe display helpers - access keys must never leak into logs.
    # ------------------------------------------------------------------ #

    @property
    def masked_access_key_id(self) -> Optional[str]:
        return mask_secret(self.access_key_id)

    def to_log_dict(self) -> dict[str, Any]:
        """A redacted, log-safe view of the event."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "provider": self.provider.value,
            "account_id": self.account_id,
            "principal_id": self.principal_id,
            "principal_name": self.principal_name,
            "principal_type": self.principal_type.value,
            "identity_key": self.identity_key,
            "event_source": self.event_source,
            "event_name": self.event_name,
            "api_family": self.api_family,
            "read_or_write": self.read_or_write.value,
            "privilege_change": self.privilege_change,
            "source_ip": self.source_ip,
            "country": self.country,
            "asn": self.asn,
            "region": self.region,
            "access_key_id": self.masked_access_key_id,
            "mfa_authenticated": self.mfa_authenticated,
            "warnings": list(self.normalization_warnings),
        }

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            "IdentityActivityEvent("
            f"event_id={self.event_id!r}, "
            f"event_name={self.event_name!r}, "
            f"principal={self.principal_name or self.principal_id!r}, "
            f"timestamp={self.timestamp.isoformat()!r})"
        )


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #


class IdentitySession(BaseModel):
    """A contiguous period of activity by one identity from one context."""

    model_config = ConfigDict(extra="forbid")

    session_key: str
    identity_key: str
    provider: CloudProvider = CloudProvider.AWS
    account_id: Optional[str] = None
    principal_id: str
    principal_name: Optional[str] = None
    baseline_category: BaselineCategory = BaselineCategory.UNKNOWN

    start_time: datetime
    last_seen: datetime

    source_ip: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None
    user_agent: Optional[str] = None
    region: Optional[str] = None

    event_count: int = 0
    unique_services: int = 0
    privilege_changes: int = 0
    api_count: int = 0
    event_ids: list[str] = Field(default_factory=list)

    # Populated by the Part 2 scorer.
    risk_score: Optional[float] = None

    @field_validator("start_time", "last_seen", mode="after")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("source_ip", mode="after")
    @classmethod
    def _validate_ip(cls, value: Optional[str]) -> Optional[str]:
        return normalize_ip(value)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.last_seen - self.start_time).total_seconds())

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"IdentitySession(session_key={self.session_key!r}, "
            f"principal={self.principal_name or self.principal_id!r}, "
            f"events={self.event_count})"
        )


# --------------------------------------------------------------------------- #
# Behavior profile
# --------------------------------------------------------------------------- #


class IdentityProfile(BaseModel):
    """Behavioral profile ("what normal looks like") for one identity + window.

    Distribution fields map a feature value to its historical frequency in
    ``[0, 1]``. They are produced by ``baseline.py`` (Part 2) and consumed by
    ``features.py``.
    """

    model_config = ConfigDict(extra="forbid")

    identity_key: str
    provider: CloudProvider = CloudProvider.AWS
    account_id: Optional[str] = None
    principal_id: str
    principal_name: Optional[str] = None
    principal_type: PrincipalType = PrincipalType.UNKNOWN
    identity_kind: IdentityKind = IdentityKind.UNKNOWN
    baseline_category: BaselineCategory = BaselineCategory.UNKNOWN
    role_arn: Optional[str] = None
    department: Optional[str] = None
    team: Optional[str] = None

    window_days: int
    observation_start: Optional[datetime] = None
    observation_end: Optional[datetime] = None

    event_count: int = 0
    distinct_days: int = 0

    normal_hours: dict[str, float] = Field(default_factory=dict)
    normal_days: dict[str, float] = Field(default_factory=dict)
    normal_countries: dict[str, float] = Field(default_factory=dict)
    normal_asns: dict[str, float] = Field(default_factory=dict)
    normal_ip_ranges: dict[str, float] = Field(default_factory=dict)
    normal_user_agents: dict[str, float] = Field(default_factory=dict)
    normal_regions: dict[str, float] = Field(default_factory=dict)
    normal_services: dict[str, float] = Field(default_factory=dict)
    normal_api_families: dict[str, float] = Field(default_factory=dict)
    normal_role_assumptions: dict[str, float] = Field(default_factory=dict)

    avg_events_per_hour: float = 0.0
    std_events_per_hour: float = 0.0
    read_write_ratio: float = 0.0
    normal_privilege_level: str = "UNKNOWN"
    mfa_expected: bool = False

    baseline_quality: BaselineQuality = BaselineQuality.COLD_START
    baseline_version: int = 0
    updated_at: Optional[datetime] = None

    @field_validator("observation_start", "observation_end", "updated_at", mode="after")
    @classmethod
    def _to_utc(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        return ensure_utc(value)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"IdentityProfile(identity_key={self.identity_key!r}, "
            f"window_days={self.window_days}, events={self.event_count}, "
            f"quality={self.baseline_quality.value})"
        )


__all__ = [
    "AccessType",
    "ApiFamilies",
    "BaselineCategory",
    "BaselineQuality",
    "CloudProvider",
    "EventCategory",
    "IdentityActivityEvent",
    "IdentityKind",
    "IdentityProfile",
    "IdentitySession",
    "IpIntelligence",
    "PRIVILEGE_MUTATION_FAMILIES",
    "PrincipalType",
    "ResolvedIdentity",
    "Severity",
    "ensure_utc",
    "fingerprint_secret",
    "mask_secret",
    "normalize_ip",
    "utcnow",
]
