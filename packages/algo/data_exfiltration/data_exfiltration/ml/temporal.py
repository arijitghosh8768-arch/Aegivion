"""Temporal rolling features over normalized event streams.

Computes trailing-window counters (5m/15m/1h/6h/24h) for cumulative
bytes, objects, requests, external bytes, unique resources/destinations,
and sensitive objects/bytes. Byte categories (observed/estimated) stay
separate; the conservative per-category maximum is the primary value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.enrichment import is_public_destination
from algo.data_exfiltration.data_exfiltration.schemas import DataActivityEvent, SensitivityLevel

TEMPORAL_WINDOWS: tuple[float, ...] = (300.0, 900.0, 3600.0, 21600.0, 86400.0)

_NON_SENSITIVE = {None, SensitivityLevel.NONE, SensitivityLevel.PUBLIC}


@dataclass
class TemporalFeatures:
    """Rolling counters at one point in time, per window size."""

    as_of_epoch_ms: float
    cumulative_bytes: dict[str, float] = field(default_factory=dict)
    """window label -> primary (max-category) bytes"""
    cumulative_objects: dict[str, float] = field(default_factory=dict)
    cumulative_requests: dict[str, float] = field(default_factory=dict)
    cumulative_external_bytes: dict[str, float] = field(default_factory=dict)
    unique_resources: dict[str, int] = field(default_factory=dict)
    unique_destinations: dict[str, int] = field(default_factory=dict)
    sensitive_objects: dict[str, int] = field(default_factory=dict)
    sensitive_bytes: dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "as_of_epoch_ms": self.as_of_epoch_ms,
            "cumulative_bytes": dict(self.cumulative_bytes),
            "cumulative_objects": dict(self.cumulative_objects),
            "cumulative_requests": dict(self.cumulative_requests),
            "cumulative_external_bytes": dict(self.cumulative_external_bytes),
            "unique_resources": dict(self.unique_resources),
            "unique_destinations": dict(self.unique_destinations),
            "sensitive_objects": dict(self.sensitive_objects),
            "sensitive_bytes": dict(self.sensitive_bytes),
        }


def _label(window: float) -> str:
    return {300.0: "5m", 900.0: "15m", 3600.0: "1h", 21600.0: "6h", 86400.0: "24h"}.get(
        window, f"{int(window)}s"
    )


def compute_temporal_features(
    events: Sequence[DataActivityEvent],
    *,
    as_of_epoch_ms: float,
    actor_id: str | None = None,
    windows: Sequence[float] = TEMPORAL_WINDOWS,
) -> TemporalFeatures:
    """Trailing-window counters for one actor (or all events when actor None)."""
    out = TemporalFeatures(as_of_epoch_ms=as_of_epoch_ms)
    for window in windows:
        label = _label(window)
        start = as_of_epoch_ms - window * 1000.0

        bytes_by_cat: dict[tuple[str, str], float] = {}
        objects = 0
        requests = 0
        resources: set[str] = set()
        destinations: set[str] = set()
        sensitive_objects = 0
        sensitive_bytes = 0.0
        external_bytes = 0.0

        for event in events:
            ts = event.event_time_epoch_ms
            if ts is None or ts < start or ts > as_of_epoch_ms:
                continue
            if actor_id is not None and event.actor_id != actor_id:
                continue

            if event.bytes_accessed is not None:
                for m in event.bytes_accessed.measurements:
                    key = (m.source.value, m.confidence.value)
                    bytes_by_cat[key] = bytes_by_cat.get(key, 0.0) + m.value
                    if event.sensitivity_level not in _NON_SENSITIVE:
                        sensitive_bytes += m.value
            if event.objects_accessed:
                objects += event.objects_accessed
                if event.sensitivity_level not in _NON_SENSITIVE:
                    sensitive_objects += event.objects_accessed
            if event.request_count:
                requests += event.request_count
            if event.resource_id:
                resources.add(event.resource_id)
            if event.destination_ip:
                destinations.add(event.destination_ip)
                if is_public_destination(event.destination_ip) is True and event.bytes_accessed is not None:
                    external_bytes += max(
                        (m.value for m in event.bytes_accessed.measurements), default=0.0
                    )

        out.cumulative_bytes[label] = max(bytes_by_cat.values()) if bytes_by_cat else 0.0
        out.cumulative_objects[label] = float(objects)
        out.cumulative_requests[label] = float(requests)
        out.cumulative_external_bytes[label] = external_bytes
        out.unique_resources[label] = len(resources)
        out.unique_destinations[label] = len(destinations)
        out.sensitive_objects[label] = sensitive_objects
        out.sensitive_bytes[label] = sensitive_bytes
    return out


def burst_and_slow_features(tf: TemporalFeatures) -> dict[str, float | None]:
    """Derived burst/slow-movement indicators from the rolling windows.

    - ``burst_ratio``: 5m bytes vs 24h bytes (high = burst concentration)
    - ``slow_ratio``: 24h bytes vs peak-hour bytes (high = slow spread)
    """
    b5 = tf.cumulative_bytes.get("5m", 0.0)
    b24 = tf.cumulative_bytes.get("24h", 0.0)
    b1h = tf.cumulative_bytes.get("1h", 0.0)
    burst = (b5 / b24) if b24 > 0 else None
    slow = (b24 / b1h) if b1h > 0 else None
    return {"burst_ratio": burst, "slow_ratio": slow}
