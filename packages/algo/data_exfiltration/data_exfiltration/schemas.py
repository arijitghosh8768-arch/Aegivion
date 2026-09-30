"""Provider-neutral event/session/profile schemas for Algorithm #2.

Design rules enforced here:

1. Nothing is invented. If a telemetry source does not provide a value the
   field stays ``None`` and the corresponding presence/quality slot records
   ``unavailable``.
2. Every derived or provided measurement carries provenance: where it came
   from (``MeasurementSource``) and how much to trust it
   (``MeasurementConfidence``).
3. Measurements from incompatible sources are represented as
   ``MultiSourceMeasurement`` rather than silently merged.
4. Sensitivity is external enrichment (e.g. Macie). This engine never
   classifies content itself and never guesses sensitivity.

All schemas are pydantic models so invalid telemetry fails loudly instead
of polluting downstream behavior models.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from algo.data_exfiltration.data_exfiltration.exceptions import MalformedEventError
from algo.data_exfiltration.data_exfiltration.measurement import (
    MeasurementConfidence,
    MeasurementSource,
    MultiSourceMeasurement,
    OptionalMeasurements,
    ValuePresence,
    optional_measurement,
    simple_measurement,
)


class Provider(str, Enum):
    """Cloud providers. AWS ships first; Azure/GCP are schema-reserved."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    GENERIC = "generic"


class ActorType(str, Enum):
    """What kind of principal performed the action."""

    IAM_USER = "iam_user"
    ASSUMED_ROLE = "assumed_role"
    FEDERATED_USER = "federated_user"
    SERVICE = "service"
    UNKNOWN = "unknown"


class DataAction(str, Enum):
    """Canonical action taxonomy for cloud data-plane activity."""

    READ_OBJECT = "read_object"
    WRITE_OBJECT = "write_object"
    DELETE_OBJECT = "delete_object"
    LIST = "list"
    ENUMERATE = "enumerate"
    COPY = "copy"
    RESTORE = "restore"
    QUERY = "query"
    EXECUTE = "execute"
    BATCH_READ = "batch_read"
    BATCH_WRITE = "batch_write"
    UNKNOWN = "unknown"


class ReadOrWrite(str, Enum):
    READ = "read"
    WRITE = "write"
    BOTH = "both"
    NEUTRAL = "neutral"


class SessionRiskState(str, Enum):
    """Lifecycle state of a session inside the detection pipeline.

    Part 1 never emits ``flagged``; that happens once risk fusion exists.
    """

    NEW = "new"
    ANALYZED = "analyzed"
    FLAGGED = "flagged"
    DISMISSED = "dismissed"


class SensitivityLevel(str, Enum):
    """Discrete sensitivity classification supplied by external enrichment."""

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


class FindingType(str, Enum):
    """Finding taxonomy. Only DISCOVERY is produced by this engine."""

    DATA_DISCOVERY = "data_discovery"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _map_sensitivity_level(level: str | SensitivityLevel | None) -> SensitivityLevel | None:
    """Map free-text source sensitivity labels onto the canonical enum.

    Unknown labels are preserved as ``None`` (unavailable), never guessed.
    """
    if level is None:
        return None
    value = str(getattr(level, "value", level)).strip().lower()
    aliases = {
        "": None,
        "none": SensitivityLevel.NONE,
        "public": SensitivityLevel.PUBLIC,
        "internal": SensitivityLevel.INTERNAL,
        "confidential": SensitivityLevel.CONFIDENTIAL,
        "restricted": SensitivityLevel.RESTRICTED,
        "private": SensitivityLevel.INTERNAL,
        "sensitive": SensitivityLevel.CONFIDENTIAL,
        "personal_information": SensitivityLevel.PII,
        "personal": SensitivityLevel.PII,
        "pii": SensitivityLevel.PII,
        "health_information": SensitivityLevel.PHI,
        "phi": SensitivityLevel.PHI,
        "financial": SensitivityLevel.FINANCIAL,
        "financial_information": SensitivityLevel.FINANCIAL,
        "credentials": SensitivityLevel.SECRETS,
        "secrets": SensitivityLevel.SECRETS,
        "secret": SensitivityLevel.SECRETS,
        "critical": SensitivityLevel.CRITICAL,
    }
    return aliases.get(value)


class DataActivityEvent(BaseModel):
    """Canonical provider-neutral record of one cloud data-plane activity.

    Every field that a source did not provide stays ``None`` and is
    mirrored in the corresponding presence slot (``*_availability``) as
    ``unavailable``. Derived numeric fields carry explicit provenance via
    ``MultiSourceMeasurement``.
    """

    model_config = ConfigDict(frozen=False, extra="ignore", populate_by_name=True)

    # -- identity -----------------------------------------------------------
    event_id: str
    provider: Provider
    account_id: str | None = None
    region: str | None = None
    timestamp: Any = None
    event_time_epoch_ms: float | None = None

    # -- actor --------------------------------------------------------------
    actor_id: str | None = None
    actor_type: ActorType = ActorType.UNKNOWN
    session_id: str | None = None

    # -- resource -----------------------------------------------------------
    resource_id: str | None = None
    resource_type: str | None = None
    resource_arn: str | None = None

    # -- action -------------------------------------------------------------
    data_action: DataAction = DataAction.UNKNOWN
    data_operation: str | None = None
    read_or_write: ReadOrWrite = ReadOrWrite.NEUTRAL
    error_code: str | None = None

    # -- object / data location --------------------------------------------
    bucket: str | None = None
    object_key: str | None = None
    database: str | None = None
    schema_name: str | None = Field(default=None, alias="schema")
    table: str | None = None
    record_count: int | None = None
    request_count: int | None = None

    # -- measurements -------------------------------------------------------
    bytes_accessed: MultiSourceMeasurement | None = None
    network_bytes: MultiSourceMeasurement | None = None
    network_packets: MultiSourceMeasurement | None = None
    objects_accessed: int | None = None

    # -- availability of measurements ---------------------------------------
    # ``*_availability`` carries the provenance-grade of the measurement;
    # ``*_presence`` is the spec vocabulary (available/unavailable/estimated/
    # observed) and is kept in sync automatically.
    bytes_accessed_availability: MeasurementConfidence = MeasurementConfidence.UNAVAILABLE
    network_bytes_availability: MeasurementConfidence = MeasurementConfidence.UNAVAILABLE
    objects_accessed_availability: MeasurementConfidence = MeasurementConfidence.UNAVAILABLE

    bytes_accessed_presence: ValuePresence = ValuePresence.UNAVAILABLE
    network_bytes_presence: ValuePresence = ValuePresence.UNAVAILABLE
    objects_accessed_presence: ValuePresence = ValuePresence.UNAVAILABLE

    # -- network context ----------------------------------------------------
    source_ip: str | None = None
    source_country: str | None = None
    source_asn: str | None = None
    user_agent: str | None = None
    destination_ip: str | None = None
    destination_country: str | None = None
    destination_asn: str | None = None
    destination_domain: str | None = None
    destination_provider: str | None = None

    # -- workload context ---------------------------------------------------
    application: str | None = None
    workload_id: str | None = None

    # -- sensitivity (external enrichment only) ------------------------------
    sensitivity_level: SensitivityLevel | None = None
    sensitivity_score: MultiSourceMeasurement | None = None
    sensitivity_source: str | None = None

    # -- raw telemetry reference --------------------------------------------
    raw_event_reference: str | None = None

    # per-field provenance for derived fields (not part of serialized model)
    _field_provenance: dict[str, dict[str, Any]] = PrivateAttr(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_timestamp(cls, data: Any) -> Any:
        if isinstance(data, dict) and data.get("timestamp") is not None:
            data = dict(data)
            ts = data.pop("timestamp")
            if data.get("event_time_epoch_ms") is None:
                data["event_time_epoch_ms"] = cls._to_epoch_ms(ts)
        return data

    @staticmethod
    def _to_epoch_ms(ts: Any) -> float | None:
        if ts is None:
            return None
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, str):
            from datetime import datetime, timezone

            text = ts.strip().replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp() * 1000.0
        from datetime import datetime, timezone

        if isinstance(ts, datetime):
            dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
            return dt.timestamp() * 1000.0
        return None

    @model_validator(mode="after")
    def _validate(self) -> "DataActivityEvent":
        # Timestamp is mandatory for session construction.
        if self.event_time_epoch_ms is None:
            raise MalformedEventError(
                "event_time_epoch_ms (or a parsable timestamp) is required",
                raw_event=None,
            )
        # Sensitivity can only arrive with a named enrichment source.
        if (self.sensitivity_level or self.sensitivity_score is not None) and not self.sensitivity_source:
            raise MalformedEventError(
                "sensitivity requires sensitivity_source (external enrichment)",
                raw_event=None,
            )
        return self

    # -- helpers -------------------------------------------------------------

    def with_provenance(
        self,
        field: str,
        source: MeasurementSource,
        confidence: MeasurementConfidence,
    ) -> "DataActivityEvent":
        """Attach provenance for a derived field, returning a mutated copy."""
        prov = dict(self._provenance())
        prov[field] = {"source": source, "confidence": confidence}
        new = self.model_copy(deep=True)
        object.__setattr__(new, "_field_provenance", prov)
        return new

    def _provenance(self) -> dict:
        return dict(getattr(self, "_field_provenance", {}))

    @property
    def field_provenance(self) -> dict:
        """Provenance for derived fields: ``{field: {source, confidence}}``."""
        return self._provenance()


class DataAccessSession(BaseModel):
    """Per-actor burst of related data activity.

    Aggregates hold explicitly named categories — they are sums of
    per-event measurements, not estimates, and every category is empty
    (zero) unless at least one contributing event measured it.
    """

    model_config = ConfigDict(frozen=False)

    session_id: str
    actor_id: str | None = None
    provider: Provider = Provider.GENERIC

    start_time: Any = None
    end_time: Any = None
    start_time_epoch_ms: float | None = None
    end_time_epoch_ms: float | None = None

    event_count: int = 0
    resources_accessed: list[str] = Field(default_factory=list)
    objects_accessed: int = 0
    bytes_accessed: MultiSourceMeasurement | None = None
    network_egress_bytes: MultiSourceMeasurement | None = None

    # destination / network diversity (observed values only)
    unique_destinations: list[str] = Field(default_factory=list)
    unique_asns: list[str] = Field(default_factory=list)
    unique_countries: list[str] = Field(default_factory=list)

    request_count: int = 0
    read_event_count: int = 0
    write_event_count: int = 0
    enumerate_list_count: int = 0
    error_event_count: int = 0

    # sensitivity aggregation from contributing events
    sensitivity_summary: OptionalMeasurements | None = None

    # analysis hooks populated later stages
    session_features: dict[str, Any] = Field(default_factory=dict)
    risk_state: SessionRiskState = SessionRiskState.NEW

    # contributing event ids (raw telemetry stays referencable)
    event_ids: list[str] = Field(default_factory=list)


class DataResourceProfile(BaseModel):
    """Per-resource view of who normally accesses what, when, how much.

    Part 1 records observed history as structured counts. Baseline
    statistics derived from it are produced by :mod:`.baseline`.
    """

    model_config = ConfigDict(frozen=False)

    resource_id: str
    resource_type: str | None = None
    resource_arn: str | None = None
    owner: str | None = None
    business_unit: str | None = None

    sensitivity_level: SensitivityLevel | None = None
    sensitivity_score: MultiSourceMeasurement | None = None
    sensitivity_source: str | None = None

    expected_consumers: list[str] = Field(default_factory=list)
    known_actors: list[str] = Field(default_factory=list)
    known_destinations: list[str] = Field(default_factory=list)
    known_workloads: list[str] = Field(default_factory=list)

    # observed aggregate activity, grouped by hour-of-day bucket
    normal_access_hours: dict[str, int] = Field(default_factory=dict)
    normal_access_volume: MultiSourceMeasurement | None = None
    normal_object_count: MultiSourceMeasurement | None = None
    normal_request_rate: MultiSourceMeasurement | None = None

    history_event_count: int = 0


class BaselineComponent(BaseModel):
    """A single named statistic inside a behavioral baseline version."""

    name: str
    value: float
    sample_count: int
    method: str | None = None


class DataBaselineVersion(BaseModel):
    """An immutable, versioned behavioral baseline over sessions."""

    model_config = ConfigDict(frozen=True)

    version_id: str
    created_at_epoch_ms: float
    session_count: int = 0
    components: dict[str, BaselineComponent] = Field(default_factory=dict)


class DataBehavioralFeatures(BaseModel):
    """Extracted behavioral features for one session.

    Part 1 implements deterministic, fully explained feature extraction.
    Every feature carries a short ``description`` documenting exactly how
    it was computed — no black boxes.
    """

    model_config = ConfigDict(frozen=False)

    session_id: str
    actor_id: str | None = None
    duration_seconds: float | None = None
    event_count: int = 0

    bytes_total: float | None = None
    bytes_total_provenance: dict[str, Any] | None = None
    bytes_per_second: float | None = None
    objects_accessed: int = 0
    request_count: int = 0
    distinct_resources: int = 0
    distinct_buckets: int | None = None

    read_write_ratio: float | None = None
    enumerate_list_count: int = 0
    error_count: int = 0

    unique_destinations: int | None = None
    unique_asns: int | None = None
    unique_countries: int | None = None
    egress_bytes: float | None = None
    egress_bytes_provenance: dict[str, Any] | None = None

    max_sensitivity: float | None = None
    sensitive_object_count: int = 0

    start_hour_utc: int | None = None
    descriptions: dict[str, str] = Field(default_factory=dict)


class SecurityFinding(BaseModel):
    """Provider-neutral finding, compatible with a central finding model.

    Part 1 produces only ``finding_type = DATA_DISCOVERY`` records that
    document observations. No risk score, severity, or exfiltration
    verdict is computed here — those arrive with risk fusion (Part 2).
    """

    model_config = ConfigDict(frozen=False)

    finding_id: str
    detector_name: str
    finding_type: FindingType = FindingType.DATA_DISCOVERY
    severity: FindingSeverity | None = None
    confidence: float | None = None
    risk_score: float | None = None

    title: str
    description: str
    observed_at_epoch_ms: float
    provider: Provider = Provider.GENERIC
    account_id: str | None = None
    region: str | None = None
    actor_id: str | None = None
    resource_id: str | None = None
    session_id: str | None = None

    arde: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Part 3: full model identity of the scoring stack that produced this finding
    model: dict[str, Any] = Field(default_factory=dict)
    """model_name, model_version, feature_version, baseline_version,
    scoring_version, variant (see ml.versioning.ModelVersionInfo)."""


# ---------------------------------------------------------------------------
# Convenience builders used by normalizers
# ---------------------------------------------------------------------------


def measurement(
    value: float,
    source: MeasurementSource,
    confidence: MeasurementConfidence,
) -> MultiSourceMeasurement:
    """Build a single-source measurement with explicit provenance."""
    return simple_measurement(value=value, source=source, confidence=confidence)


def optional(
    value: float | None,
    source: MeasurementSource | None,
    confidence: MeasurementConfidence | None,
) -> OptionalMeasurements:
    """Build an optional measurement, or an explicit 'unavailable' marker."""
    return optional_measurement(value=value, source=source, confidence=confidence)


def iter_measurement_fields(model: BaseModel) -> Iterable[str]:
    """Yield names of MultiSourceMeasurement fields on a model."""
    for name in type(model).model_fields:
        value = getattr(model, name)
        if isinstance(value, MultiSourceMeasurement):
            yield name
