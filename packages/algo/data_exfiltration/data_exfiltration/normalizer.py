"""Event normalization: raw telemetry -> canonical DataActivityEvent.

Design rules:

- One class per telemetry source (``normalize_cloudtrail``,
  ``normalize_vpc_flow``, ...). Cloud-specific knowledge lives only here.
- A record that is structurally fine but not a supported data-plane event
  raises :class:`UnsupportedEventError` (skipped, not an error).
- A record that cannot be honestly normalized raises
  :class:`MalformedEventError` carrying the raw payload — nothing is
  silently dropped or invented.
- Bytes and measurements are taken only from fields the source actually
  provides, each with explicit provenance (source + confidence).
- Geographic context (country/ASN) is NEVER guessed from an IP. Enrichment
  happens only via an explicitly provided :class:`GeoEnricher`.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, Protocol

from algo.data_exfiltration.data_exfiltration.exceptions import (
    MalformedEventError,
    SchemaVersionError,
    UnsupportedEventError,
)
from algo.data_exfiltration.data_exfiltration.measurement import (
    MeasurementConfidence,
    MeasurementSource,
    simple_measurement,
)
from algo.data_exfiltration.data_exfiltration.raw_store import RawEventStore
from algo.data_exfiltration.data_exfiltration.schemas import (
    ActorType,
    DataAction,
    DataActivityEvent,
    Provider,
    ReadOrWrite,
    SensitivityLevel,
    _map_sensitivity_level,
)

# S3 request parameters that indicate list/enumerate style operations
_LIST_PARAM_HINTS = ("prefix", "maxResults", "continuation-token", "delimiter")

_ARN_RE = re.compile(r"^arn:[^:]*:[^:]*:[^:]*:[^:]*:.+$")

# eventVersion prefixes this normalizer can read
_SUPPORTED_SCHEMA_VERSIONS = ("1.",)


class GeoEnricher(Protocol):
    """Optional external IP -> {country, asn} enrichment.

    Implementations must return None for unknown IPs; the normalizer never
    fabricates geography.
    """

    def lookup(self, ip: str) -> dict[str, str | None] | None: ...


class EventNormalizer:
    """Converts provider telemetry into canonical DataActivityEvent records."""

    def __init__(self, geo_enricher: GeoEnricher | None = None) -> None:
        self._geo = geo_enricher

    # ------------------------------------------------------------------
    # public entry points
    # ------------------------------------------------------------------

    def normalize(
        self,
        provider: Provider,
        record: dict[str, Any],
        raw_store: RawEventStore | None = None,
    ) -> DataActivityEvent:
        """Normalize one record with the normalizer registered for *provider*."""
        normalizer: Callable[..., DataActivityEvent] | None = {
            Provider.AWS: self.normalize_cloudtrail,
            Provider.GENERIC: self.normalize_generic,
        }.get(provider)
        if normalizer is None:
            raise UnsupportedEventError(f"no normalizer registered for provider {provider}")
        return normalizer(record, raw_store=raw_store)

    def normalize_generic(
        self,
        record: dict[str, Any],
        raw_store: RawEventStore | None = None,
    ) -> DataActivityEvent:
        """Normalize an already-canonical record (useful for tests/other clouds).

        Accepts the canonical field names directly; provenance defaults to
        ``normalizer``/``observed`` because the caller asserts the values.
        """
        if not isinstance(record, dict):
            raise MalformedEventError("generic record must be a dict", raw_event=record)
        event_id = str(record.get("event_id") or "")
        if not event_id:
            raise MalformedEventError("generic record missing event_id", raw_event=record)
        raw_ref = raw_store.store(record) if raw_store is not None else None
        try:
            return DataActivityEvent(
                event_id=event_id,
                provider=Provider(str(record.get("provider") or Provider.GENERIC.value)),
                account_id=record.get("account_id"),
                region=record.get("region"),
                timestamp=record.get("timestamp"),
                event_time_epoch_ms=record.get("event_time_epoch_ms"),
                actor_id=record.get("actor_id"),
                session_id=record.get("session_id"),
                resource_id=record.get("resource_id"),
                resource_type=record.get("resource_type"),
                resource_arn=record.get("resource_arn"),
                data_action=DataAction(str(record.get("data_action") or DataAction.UNKNOWN.value)),
                data_operation=record.get("data_operation"),
                read_or_write=ReadOrWrite(str(record.get("read_or_write") or ReadOrWrite.NEUTRAL.value)),
                bucket=record.get("bucket"),
                object_key=record.get("object_key"),
                bytes_accessed=(
                    simple_measurement(
                        float(record["bytes_accessed"]),
                        MeasurementSource.NORMALIZER,
                        MeasurementConfidence.OBSERVED,
                        detail="generic canonical input",
                    )
                    if record.get("bytes_accessed") is not None
                    else None
                ),
                objects_accessed=record.get("objects_accessed"),
                source_ip=record.get("source_ip"),
                destination_ip=record.get("destination_ip"),
                user_agent=record.get("user_agent"),
                raw_event_reference=raw_ref,
            )
        except Exception as exc:
            raise MalformedEventError(f"generic normalization failed: {exc}", raw_event=record, cause=exc) from exc

    # ------------------------------------------------------------------
    # AWS CloudTrail data events
    # ------------------------------------------------------------------

    def normalize_cloudtrail(
        self,
        record: dict[str, Any],
        raw_store: RawEventStore | None = None,
    ) -> DataActivityEvent:
        """Normalize one AWS CloudTrail record (data events only)."""
        if not isinstance(record, dict):
            raise MalformedEventError("CloudTrail record must be a dict", raw_event=record)

        version = str(record.get("eventVersion") or "")
        if version and not version.startswith(_SUPPORTED_SCHEMA_VERSIONS):
            raise SchemaVersionError(f"unsupported CloudTrail eventVersion {version!r}")

        event_name = record.get("eventName")
        if not isinstance(event_name, str) or not event_name:
            raise MalformedEventError("CloudTrail record missing eventName", raw_event=record)

        event_source = str(record.get("eventSource") or "")
        mapped = _map_cloudtrail_event(event_source, event_name, record)
        if mapped is None:
            raise UnsupportedEventError(
                f"not a supported data event: {event_source}.{event_name}"
            )
        action, read_or_write, operation = mapped

        # --- identity -----------------------------------------------------
        identity = record.get("userIdentity") or {}
        id_type = str(identity.get("type") or record.get("type") or "Unknown")
        actor_id, actor_type = _extract_actor(identity, record, id_type)

        # --- timestamps ---------------------------------------------------
        event_time = record.get("eventTime")
        if not isinstance(event_time, str):
            raise MalformedEventError("CloudTrail record missing eventTime", raw_event=record)

        # --- resource ------------------------------------------------------
        bucket, object_key, table, database = _extract_s3_or_db_target(event_source, record)
        resource_id, resource_arn = _derive_resource(
            event_source, bucket=bucket, table=table, record=record
        )

        # --- measurements ---------------------------------------------------
        bytes_out = _coerce_bytes(record.get("additionalEventData", {}).get("bytesTransferredOut")
                                  if isinstance(record.get("additionalEventData"), dict) else None)
        bytes_in = _coerce_bytes(record.get("additionalEventData", {}).get("bytesTransferredIn")
                                 if isinstance(record.get("additionalEventData"), dict) else None)

        bytes_measurement = None
        bytes_confidence = MeasurementConfidence.UNAVAILABLE
        if bytes_out is not None or bytes_in is not None:
            # CloudTrail reports transferred bytes as a size delta: an estimate.
            primary = max(v for v in (bytes_out, bytes_in) if v is not None)
            bytes_measurement = simple_measurement(
                float(primary),
                MeasurementSource.CLOUDTRAIL,
                MeasurementConfidence.ESTIMATED,
                detail=f"bytesTransferredOut={bytes_out} bytesTransferredIn={bytes_in}",
            )
            bytes_confidence = MeasurementConfidence.ESTIMATED

        # --- network context ------------------------------------------------
        source_ip = _coerce_ip(record.get("sourceIPAddress"))
        geo = self._geo.lookup(source_ip) if (self._geo and source_ip) else None

        raw_ref = raw_store.store(record) if raw_store is not None else None

        try:
            event = DataActivityEvent(
                event_id=str(record.get("eventID") or f"ct-{_stable_id(record)}"),
                provider=Provider.AWS,
                account_id=str(record.get("recipientAccountId") or identity.get("accountId") or record.get("accountId") or "") or None,
                region=record.get("awsRegion"),
                timestamp=event_time,
                actor_id=actor_id,
                actor_type=actor_type,
                resource_id=resource_id,
                resource_type=_resource_type(event_source),
                resource_arn=resource_arn,
                data_action=action,
                data_operation=operation,
                read_or_write=read_or_write,
                error_code=record.get("errorCode"),
                bucket=bucket,
                object_key=object_key,
                table=table,
                database=database,
                request_count=1,
                bytes_accessed=bytes_measurement,
                bytes_accessed_availability=bytes_confidence,
                bytes_accessed_presence="estimated" if bytes_measurement is not None else "unavailable",
                objects_accessed=1 if (bucket and object_key) else None,
                objects_accessed_availability=(
                    MeasurementConfidence.OBSERVED if (bucket and object_key) else MeasurementConfidence.UNAVAILABLE
                ),
                objects_accessed_presence="observed" if (bucket and object_key) else "unavailable",
                network_bytes_availability=MeasurementConfidence.UNAVAILABLE,
                network_bytes_presence="unavailable",
                source_ip=source_ip,
                user_agent=record.get("userAgent") or None,
                destination_country=(geo or {}).get("country"),
                destination_asn=(geo or {}).get("asn"),
                raw_event_reference=raw_ref,
            )
        except Exception as exc:
            raise MalformedEventError(f"CloudTrail normalization failed: {exc}", raw_event=record, cause=exc) from exc

        return event

    # ------------------------------------------------------------------
    # AWS VPC Flow Logs
    # ------------------------------------------------------------------

    def normalize_vpc_flow(
        self,
        record: dict[str, Any],
        raw_store: RawEventStore | None = None,
    ) -> DataActivityEvent:
        """Normalize one VPC flow log record (dict form from the reader)."""
        if not isinstance(record, dict):
            raise MalformedEventError("VPC flow record must be a dict", raw_event=record)

        bytes_val = _coerce_bytes(record.get("bytes"))
        packets_val = _coerce_bytes(record.get("packets"))
        start = _coerce_bytes(record.get("start"))
        end = _coerce_bytes(record.get("end"))

        if bytes_val is None or start is None:
            raise MalformedEventError(
                "VPC flow record missing bytes/start", raw_event=record
            )

        src = _coerce_ip(record.get("src-addr") or record.get("srcaddr"))
        dst = _coerce_ip(record.get("dst-addr") or record.get("dstaddr"))
        src_geo = self._geo.lookup(src) if (self._geo and src) else None
        dst_geo = self._geo.lookup(dst) if (self._geo and dst) else None

        raw_ref = raw_store.store(record) if raw_store is not None else None

        flow_id = f"flow-{_stable_id(record)}"
        try:
            return DataActivityEvent(
                event_id=flow_id,
                provider=Provider.AWS,
                account_id=str(record.get("account-id") or record.get("account_id") or "") or None,
                region=record.get("region"),
                event_time_epoch_ms=float(start) * 1000.0,
                actor_id=record.get("instance-id") if record.get("instance-id") not in (None, "-") else None,
                actor_type=ActorType.SERVICE,
                resource_id=record.get("interface-id") or record.get("interface_id"),
                resource_type="network_interface",
                data_action=DataAction.UNKNOWN,
                data_operation="vpc_flow",
                read_or_write=ReadOrWrite.NEUTRAL,
                bytes_accessed=None,
                bytes_accessed_availability=MeasurementConfidence.UNAVAILABLE,
                bytes_accessed_presence="unavailable",
                network_bytes=(
                    simple_measurement(
                        float(bytes_val),
                        MeasurementSource.VPC_FLOW_LOG,
                        MeasurementConfidence.OBSERVED,
                        detail="vpc flow bytes",
                    )
                ),
                network_bytes_availability=MeasurementConfidence.OBSERVED,
                network_bytes_presence="observed",
                network_packets=(
                    simple_measurement(
                        float(packets_val),
                        MeasurementSource.VPC_FLOW_LOG,
                        MeasurementConfidence.OBSERVED,
                    )
                    if packets_val is not None
                    else None
                ),
                source_ip=src,
                source_country=(src_geo or {}).get("country"),
                source_asn=(src_geo or {}).get("asn"),
                destination_ip=dst,
                destination_country=(dst_geo or {}).get("country"),
                destination_asn=(dst_geo or {}).get("asn"),
                raw_event_reference=raw_ref,
            )
        except Exception as exc:
            raise MalformedEventError(f"VPC flow normalization failed: {exc}", raw_event=record, cause=exc) from exc


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def _stable_id(record: dict[str, Any]) -> str:
    """Deterministic id for records lacking a native event id."""
    blob = repr(sorted(record.items(), key=lambda kv: kv[0])).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _coerce_bytes(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        out = int(value)
    except (TypeError, ValueError):
        return None
    return out if out >= 0 else None


def _coerce_ip(value: Any) -> str | None:
    """Return the IP only when it is a real address (never internal markers)."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text in {"-", "internal", "Internal", "unknown"}:
        return None
    return text


def _resource_type(event_source: str) -> str:
    if "s3" in event_source:
        return "s3_bucket"
    if "dynamodb" in event_source:
        return "dynamodb_table"
    if "rds" in event_source:
        return "rds_database"
    return "unknown"


def _extract_actor(identity: dict[str, Any], record: dict[str, Any], id_type: str) -> tuple[str | None, ActorType]:
    """Extract (actor_id, actor_type) from CloudTrail userIdentity.

    Never invents an actor: Unidentified/anonymous callers yield None.
    """
    if id_type in {"IAMUser", "FederatedUser", "SAMLUser", "STS"}:
        arn = identity.get("arn") or record.get("arn")
        actor_type = ActorType.IAM_USER if id_type == "IAMUser" else ActorType.FEDERATED_USER
        return (arn or identity.get("principalId") or None), actor_type
    if id_type == "AssumedRole":
        arn = identity.get("arn") or record.get("arn")
        return arn, ActorType.ASSUMED_ROLE
    if id_type in {"Service", "AWSService"}:
        return identity.get("arn") or identity.get("invokedBy"), ActorType.SERVICE
    return None, ActorType.UNKNOWN


def _map_cloudtrail_event(
    event_source: str,
    event_name: str,
    record: dict[str, Any],
) -> tuple[DataAction, ReadOrWrite, str] | None:
    """Map (eventSource, eventName) -> canonical action.

    Returns None when the event is not a supported data-plane event
    (e.g. management APIs) so the caller can skip it.
    """
    if record.get("managementEvent") or record.get("eventCategory") == "Management":
        return None

    if "s3" in event_source:
        mapping = {
            "GetObject": DataAction.READ_OBJECT,
            "HeadObject": DataAction.READ_OBJECT,
            "SelectObjectContent": DataAction.QUERY,
            "CopyObject": DataAction.COPY,
            "PutObject": DataAction.WRITE_OBJECT,
            "DeleteObject": DataAction.DELETE_OBJECT,
            "DeleteObjects": DataAction.BATCH_WRITE,
            "ListObjects": DataAction.LIST,
            "ListObjectsV2": DataAction.LIST,
            "ListBucket": DataAction.LIST,
        }
        action = mapping.get(event_name)
        if action is None:
            return None
        # Object-level APIs carry a key; bucket-level List without key is
        # treated as enumeration when scoped by prefix/pagination.
        if action is DataAction.LIST:
            params = record.get("requestParameters") or {}
            if any(k in params for k in _LIST_PARAM_HINTS):
                return DataAction.ENUMERATE, ReadOrWrite.READ, event_name
        read_write = {
            DataAction.READ_OBJECT: ReadOrWrite.READ,
            DataAction.QUERY: ReadOrWrite.READ,
            DataAction.COPY: ReadOrWrite.BOTH,
            DataAction.WRITE_OBJECT: ReadOrWrite.WRITE,
            DataAction.DELETE_OBJECT: ReadOrWrite.WRITE,
            DataAction.BATCH_WRITE: ReadOrWrite.WRITE,
            DataAction.LIST: ReadOrWrite.READ,
            DataAction.ENUMERATE: ReadOrWrite.READ,
        }[action]
        return action, read_write, event_name

    if "dynamodb" in event_source:
        mapping = {
            "GetItem": DataAction.READ_OBJECT,
            "Query": DataAction.QUERY,
            "Scan": DataAction.QUERY,
            "BatchGetItem": DataAction.BATCH_READ,
            "PutItem": DataAction.WRITE_OBJECT,
            "UpdateItem": DataAction.WRITE_OBJECT,
            "DeleteItem": DataAction.DELETE_OBJECT,
            "BatchWriteItem": DataAction.BATCH_WRITE,
        }
        action = mapping.get(event_name)
        if action is None:
            return None
        read_write = ReadOrWrite.WRITE if action in (
            DataAction.WRITE_OBJECT, DataAction.DELETE_OBJECT, DataAction.BATCH_WRITE
        ) else ReadOrWrite.READ
        return action, read_write, event_name

    if "rds" in event_source or "redshift" in event_source:
        if event_name in {"ExecuteStatement", "BatchExecuteStatement"}:
            return DataAction.EXECUTE, ReadOrWrite.READ, event_name
        if event_name == "DataAPIRequest":
            return DataAction.QUERY, ReadOrWrite.READ, event_name
        return None

    return None


def _extract_s3_or_db_target(
    event_source: str, record: dict[str, Any]
) -> tuple[str | None, str | None, str | None, str | None]:
    """Extract (bucket, object_key, table, database) from requestParameters."""
    params = record.get("requestParameters")
    if not isinstance(params, dict):
        return None, None, None, None

    bucket = params.get("bucketName") or params.get("bucket")
    key = params.get("key")
    table = params.get("tableName")
    database = params.get("databaseName")

    if bucket is not None and not isinstance(bucket, str):
        bucket = None  # corrupt/complex parameter shape: leave unavailable
    if key is not None and not isinstance(key, str):
        key = None

    return (
        bucket or None,
        key or None,
        table if isinstance(table, str) else None,
        database if isinstance(database, str) else None,
    )


def _derive_resource(
    event_source: str,
    *,
    bucket: str | None,
    table: str | None,
    record: dict[str, Any],
) -> tuple[str | None, str | None]:
    """Derive (resource_id, resource_arn) from request parameters only.

    We do not reconstruct ARNs we cannot honestly derive (GAP-02). Empty
    strings and corrupted parameter shapes leave the slot unavailable.
    """
    account = record.get("recipientAccountId") or ""
    region = record.get("awsRegion") or ""
    if "s3" in event_source:
        if isinstance(bucket, str) and bucket.strip():
            return f"s3://{bucket}", None
        return None, None
    if "dynamodb" in event_source and isinstance(table, str) and table.strip():
        arn = f"arn:aws:dynamodb:{region}:{account}:table/{table}"
        return arn, arn if _ARN_RE.match(arn) else None
    return None, None
