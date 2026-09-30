"""Time-windowed aggregation over normalized events.

Volume intelligence needs "how much did X do in the last N minutes" for
N in {5m, 15m, 1h, 6h, 24h, 7d}. Aggregates keep per-(source, confidence)
byte categories separate — an observed flow byte and an estimated
CloudTrail delta never merge into one number.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Sequence

from algo.data_exfiltration.data_exfiltration.schemas import DataActivityEvent

ScopeKeyFn = Callable[[DataActivityEvent], str | None]


@dataclass
class WindowAggregate:
    """Honest sums over one time window for one scope key."""

    scope_key: str
    window_seconds: float
    end_epoch_ms: float
    event_count: int = 0
    bytes_by_category: dict[tuple[str, str], float] = field(default_factory=dict)
    objects_accessed: int = 0
    request_count: int = 0
    unique_resources: set[str] = field(default_factory=set)
    unique_objects: set[tuple[str | None, str]] = field(default_factory=set)

    @property
    def bytes_by_confidence(self) -> dict[str, float]:
        """Bytes summed per confidence grade (observed/estimated kept apart)."""
        out: dict[str, float] = defaultdict(float)
        for (_src, conf), value in self.bytes_by_category.items():
            out[conf] += value
        return dict(out)

    @property
    def max_bytes(self) -> float:
        """Largest single-category byte sum (conservative primary value)."""
        return max(self.bytes_by_category.values()) if self.bytes_by_category else 0.0

    @property
    def total_bytes(self) -> float:
        return sum(self.bytes_by_category.values())


def _event_bytes(event: DataActivityEvent) -> dict[tuple[str, str], float]:
    if event.bytes_accessed is None:
        return {}
    out: dict[tuple[str, str], float] = {}
    for m in event.bytes_accessed.measurements:
        key = (m.source.value, m.confidence.value)
        out[key] = out.get(key, 0.0) + m.value
    return out


def actor_scope(event: DataActivityEvent) -> str | None:
    return event.actor_id


def workload_scope(event: DataActivityEvent) -> str | None:
    return event.workload_id


def resource_scope(event: DataActivityEvent) -> str | None:
    return event.resource_id


def aggregate_window(
    events: Sequence[DataActivityEvent],
    *,
    scope_fn: ScopeKeyFn,
    window_seconds: float,
    end_epoch_ms: float,
    scope_key: str | None = None,
) -> dict[str, WindowAggregate]:
    """Aggregate events in [end - window, end] grouped by scope key.

    Returns a dict keyed by scope key (or a single entry when *scope_key*
    is pinned).
    """
    start_ms = end_epoch_ms - window_seconds * 1000.0
    out: dict[str, WindowAggregate] = {}
    for event in events:
        ts = event.event_time_epoch_ms
        if ts is None or ts < start_ms or ts > end_epoch_ms:
            continue
        key = scope_key if scope_key is not None else scope_fn(event)
        if key is None:
            continue
        agg = out.get(key)
        if agg is None:
            agg = out[key] = WindowAggregate(
                scope_key=key,
                window_seconds=window_seconds,
                end_epoch_ms=end_epoch_ms,
            )
        agg.event_count += 1
        for cat, value in _event_bytes(event).items():
            agg.bytes_by_category[cat] = agg.bytes_by_category.get(cat, 0.0) + value
        if event.objects_accessed is not None:
            agg.objects_accessed += event.objects_accessed
        if event.request_count is not None:
            agg.request_count += event.request_count
        if event.resource_id:
            agg.unique_resources.add(event.resource_id)
        if event.object_key:
            agg.unique_objects.add((event.bucket, event.object_key))
    return out


def scope_history(
    events: Sequence[DataActivityEvent],
    *,
    scope_fn: ScopeKeyFn,
    scope_key: str,
) -> list[DataActivityEvent]:
    """Events belonging to one scope key."""
    return [e for e in events if scope_fn(e) == scope_key]
