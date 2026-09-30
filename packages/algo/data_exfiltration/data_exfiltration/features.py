"""Session feature extraction (deterministic, fully documented).

Part 1 ships a transparent feature extractor: every feature value is
accompanied by a human-readable description of exactly how it was
computed. No ML, no hidden state, no magic thresholds. Feature vectors
are stored on sessions (``session_features``) for Part 2 to consume.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from algo.data_exfiltration.data_exfiltration.measurement import ValuePresence
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, DataBehavioralFeatures

_ENUMLIST_ACTIONS = {"enumerate", "list"}


def extract_features(session: DataAccessSession) -> DataBehavioralFeatures:
    """Extract behavioral features from one session.

    See ``DataBehavioralFeatures`` for field semantics. Every computation
    is deterministic and described in the ``descriptions`` map.
    """
    descriptions: dict[str, str] = {}

    duration_s = None
    if session.start_time_epoch_ms is not None and session.end_time_epoch_ms is not None:
        duration_s = max(0.0, (session.end_time_epoch_ms - session.start_time_epoch_ms) / 1000.0)
    descriptions["duration_seconds"] = (
        "end_time_epoch_ms minus start_time_epoch_ms, in seconds (0 if instantaneous)"
    )

    bytes_total = None
    bytes_prov = None
    if session.bytes_accessed is not None and session.bytes_accessed.measurements:
        bytes_total = max(m.value for m in session.bytes_accessed.measurements)
        bytes_prov = session.bytes_accessed.provenance()
        descriptions["bytes_total"] = (
            "sum of bytes_accessed over contributing events, taken as the "
            "maximum per-source category (observed and estimated categories "
            "kept distinct in provenance)"
        )

    bytes_per_second = None
    if bytes_total is not None and duration_s and duration_s > 0:
        bytes_per_second = bytes_total / duration_s
        descriptions["bytes_per_second"] = "bytes_total divided by duration_seconds"

    egress = None
    egress_prov = None
    if session.network_egress_bytes is not None and session.network_egress_bytes.measurements:
        egress = max(m.value for m in session.network_egress_bytes.measurements)
        egress_prov = session.network_egress_bytes.provenance()
        descriptions["egress_bytes"] = (
            "sum of network_bytes over correlated flow records (observed); "
            "maximum per-source category when multiple exist"
        )

    read_write_ratio = None
    if session.write_event_count > 0:
        read_write_ratio = session.read_event_count / session.write_event_count
    elif session.read_event_count > 0:
        read_write_ratio = float("inf")
    descriptions["read_write_ratio"] = "read_event_count / write_event_count (inf when all reads)"
    descriptions["enumerate_list_count"] = "events with a list/enumerate data_action in this session"
    descriptions["error_count"] = "events in this session that carried an error_code"

    distinct_buckets = None
    if any(r.startswith("s3://") for r in session.resources_accessed):
        distinct_buckets = len({r for r in session.resources_accessed if r.startswith("s3://")})
    descriptions["distinct_buckets"] = "count of distinct s3:// resources in resources_accessed"

    start_hour_utc = None
    if session.start_time_epoch_ms is not None:
        start_hour_utc = datetime.fromtimestamp(session.start_time_epoch_ms / 1000.0, tz=timezone.utc).hour
    descriptions["start_hour_utc"] = "UTC hour of session start"

    features = DataBehavioralFeatures(
        session_id=session.session_id,
        actor_id=session.actor_id,
        duration_seconds=duration_s,
        event_count=session.event_count,
        bytes_total=bytes_total,
        bytes_total_provenance=bytes_prov,
        bytes_per_second=bytes_per_second,
        objects_accessed=session.objects_accessed,
        request_count=session.request_count,
        distinct_resources=len(session.resources_accessed),
        distinct_buckets=distinct_buckets,
        read_write_ratio=read_write_ratio,
        enumerate_list_count=session.enumerate_list_count,
        error_count=session.error_event_count,
        unique_destinations=len(session.unique_destinations) if session.unique_destinations else None,
        unique_asns=len(session.unique_asns) if session.unique_asns else None,
        unique_countries=len(session.unique_countries) if session.unique_countries else None,
        egress_bytes=egress,
        egress_bytes_provenance=egress_prov,
        max_sensitivity=None,
        sensitive_object_count=0,
        start_hour_utc=start_hour_utc,
        descriptions=descriptions,
    )

    if session.sensitivity_summary is not None and session.sensitivity_summary.measurement is not None:
        values = [m.value for m in session.sensitivity_summary.measurement.measurements]
        if values:
            features.max_sensitivity = max(values)
            descriptions["max_sensitivity"] = (
                "maximum sensitivity_score contributed by any event "
                "(external enrichment only; None when no enrichment)"
            )
        features.descriptions = descriptions

    return features


def attach_features(session: DataAccessSession, features: DataBehavioralFeatures) -> DataAccessSession:
    """Return a copy of *session* with ``session_features`` populated."""
    payload = features.model_dump(mode="json")
    return session.model_copy(update={"session_features": payload})


def feature_vector(features: DataBehavioralFeatures) -> dict[str, float | int | None]:
    """Numeric-only view for Part 2 ML consumption (stable ordering)."""
    return {
        "duration_seconds": features.duration_seconds,
        "bytes_total": features.bytes_total,
        "bytes_per_second": features.bytes_per_second,
        "objects_accessed": features.objects_accessed,
        "request_count": features.request_count,
        "distinct_resources": features.distinct_resources,
        "distinct_buckets": features.distinct_buckets,
        "read_write_ratio": features.read_write_ratio,
        "enumerate_list_count": features.enumerate_list_count,
        "error_count": features.error_count,
        "unique_destinations": features.unique_destinations,
        "unique_asns": features.unique_asns,
        "unique_countries": features.unique_countries,
        "egress_bytes": features.egress_bytes,
        "max_sensitivity": features.max_sensitivity,
        "sensitive_object_count": features.sensitive_object_count,
        "start_hour_utc": features.start_hour_utc,
    }
