"""Rolling temporal features - **Part 2 ML layer**.

Events are never scored fully independently: the same event is ordinary at
the end of a quiet hour and alarming in the middle of a burst. This module
maintains per-identity rolling windows (5m / 15m / 1h / 24h) and derives
burst-style aggregates from them.

The tracker is *causal*: ``update`` is called with events in timestamp order
and features for an event only ever use strictly earlier events. That is the
no-leakage guarantee the ML layer depends on.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from detection.credential_compromise.schemas import (
    IdentityActivityEvent,
    ensure_utc,
)

WINDOW_MINUTES: tuple[int, ...] = (5, 15, 60, 1440)

#: Max events retained per identity before the oldest are dropped. Keeps the
#: tracker O(1)-ish in memory while still covering the 24h window.
_MAX_BUFFER = 10_000


@dataclass
class WindowStats:
    """Aggregates over one rolling window, computed causally."""

    window_minutes: int
    event_count: int = 0
    unique_services: int = 0
    unique_apis: int = 0
    privilege_changes: int = 0
    location_changes: int = 0
    network_changes: int = 0

    def as_dict(self) -> dict[str, float]:
        return {
            f"events_{self.window_minutes}m": float(self.event_count),
            f"unique_services_{self.window_minutes}m": float(self.unique_services),
            f"unique_apis_{self.window_minutes}m": float(self.unique_apis),
            f"privilege_changes_{self.window_minutes}m": float(self.privilege_changes),
            f"location_changes_{self.window_minutes}m": float(self.location_changes),
            f"network_changes_{self.window_minutes}m": float(self.network_changes),
        }


@dataclass
class _IdentityBuffer:
    timestamps: list[datetime] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    privilege: list[bool] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)

    def trim(self, cutoff: datetime) -> None:
        """Drop everything strictly older than ``cutoff``."""
        idx = bisect_left(self.timestamps, cutoff)
        if idx:
            del self.timestamps[:idx]
            del self.services[:idx]
            del self.apis[:idx]
            del self.privilege[:idx]
            del self.countries[:idx]
            del self.networks[:idx]


class TemporalTracker:
    """Per-identity rolling window state with a causal, no-leakage contract."""

    def __init__(self, *, windows_minutes: tuple[int, ...] = WINDOW_MINUTES) -> None:
        self.windows_minutes = windows_minutes
        self._buffers: dict[str, _IdentityBuffer] = {}

    def _buffer(self, identity_key: str) -> _IdentityBuffer:
        buffer = self._buffers.get(identity_key)
        if buffer is None:
            buffer = _IdentityBuffer()
            self._buffers[identity_key] = buffer
        return buffer

    def observe(self, event: IdentityActivityEvent) -> WindowStats:
        """Record an event and return the windows *as of* that event.

        Ordering contract: call with monotonically non-decreasing timestamps
        per identity. The returned stats include the event itself (its effect
        starts at its own timestamp) but no future events.
        """
        ts = ensure_utc(event.timestamp)
        identity = event.identity_key or event.principal_id
        buffer = self._buffer(identity)
        buffer.trim(ts - timedelta(minutes=max(self.windows_minutes)))
        buffer.timestamps.append(ts)
        buffer.services.append(event.service_name)
        buffer.apis.append(f"{event.service_name}:{event.event_name}")
        buffer.privilege.append(bool(event.privilege_change))
        buffer.countries.append(event.country or "")
        buffer.networks.append(event.source_ip or "")
        if len(buffer.timestamps) > _MAX_BUFFER:
            overflow = len(buffer.timestamps) - _MAX_BUFFER
            del buffer.timestamps[:overflow]
            del buffer.services[:overflow]
            del buffer.apis[:overflow]
            del buffer.privilege[:overflow]
            del buffer.countries[:overflow]
            del buffer.networks[:overflow]
        slices = self.window_slices(identity, at=ts)
        return slices[self.windows_minutes[-1]]

    def stats_for(
        self,
        identity_key: str,
        *,
        at: datetime,
    ) -> WindowStats:
        """Aggregate over the widest window ending at ``at`` (inclusive)."""
        buffer = self._buffers.get(identity_key)
        if buffer is None:
            return WindowStats(window_minutes=0)
        ts = ensure_utc(at)
        end = bisect_right(buffer.timestamps, ts)
        return self._aggregate(buffer, 0, end, self.windows_minutes[-1])

    def _aggregate(
        self,
        buffer: _IdentityBuffer,
        start: int,
        end: int,
        window_minutes: int,
    ) -> WindowStats:
        window = buffer.timestamps[start:end]
        stats = WindowStats(window_minutes=window_minutes)
        stats.event_count = len(window)
        stats.unique_services = len(set(buffer.services[start:end]))
        stats.unique_apis = len(set(buffer.apis[start:end]))
        stats.privilege_changes = sum(1 for flag in buffer.privilege[start:end] if flag)
        stats.location_changes = len(
            {c for c in buffer.countries[start:end] if c}
        )
        stats.network_changes = len({n for n in buffer.networks[start:end] if n})
        return stats

    def window_slices(self, identity_key: str, at: datetime) -> dict[int, WindowStats]:
        """Per-window aggregates ending at ``at`` (inclusive of that instant)."""
        buffer = self._buffers.get(identity_key)
        if buffer is None:
            return {minutes: WindowStats(window_minutes=minutes) for minutes in self.windows_minutes}
        ts = ensure_utc(at)
        results: dict[int, WindowStats] = {}
        for minutes in self.windows_minutes:
            start_ts = ts - timedelta(minutes=minutes)
            start = bisect_left(buffer.timestamps, start_ts)
            end = bisect_right(buffer.timestamps, ts)
            results[minutes] = self._aggregate(buffer, start, end, minutes)
        return results

    def forget(self, identity_key: str) -> None:
        self._buffers.pop(identity_key, None)


# --------------------------------------------------------------------------- #
# Derived temporal features
# --------------------------------------------------------------------------- #


def burst_score(stats_5m: WindowStats, stats_60m: WindowStats) -> float:
    """How burst-like the last 5 minutes are relative to the last hour.

    5 events in 5 minutes is unremarkable inside an active hour and striking
    after 59 minutes of silence. Normalised to [0, 1].
    """
    if stats_60m.event_count <= 0:
        return 0.0
    expected_5m = stats_60m.event_count * (5.0 / 60.0)
    if expected_5m <= 0:
        return 0.0
    ratio = stats_5m.event_count / expected_5m
    # ratio 1 = perfectly in line with the hour's pace; cap the squashing.
    return round(min(1.0, (ratio - 1.0) / 9.0) if ratio > 1 else 0.0, 4)


def temporal_vector(
    windows: dict[int, WindowStats],
    *,
    burst: Optional[float] = None,
) -> dict[str, float]:
    """Flat, stable-ordered temporal feature dict across all windows."""
    vector: dict[str, float] = {}
    for minutes in sorted(windows):
        vector.update(windows[minutes].as_dict())
    if burst is not None:
        vector["request_burst_score"] = burst
    return vector


def temporal_anomaly_score(
    windows: dict[int, WindowStats],
    *,
    burst: Optional[float] = None,
) -> float:
    """A single interpretable temporal risk score in [0, 1].

    Deliberately simple and transparent: privilege mutations and location
    churn inside a short window are the classic burst signatures. The ML model
    provides the non-linear view; this score keeps the fusion layer auditable.
    """
    stats_5m = windows.get(5) or WindowStats(window_minutes=5)
    stats_15m = windows.get(15) or WindowStats(window_minutes=15)
    score = 0.0
    if stats_5m.privilege_changes and stats_5m.event_count >= 3:
        score = max(score, 0.8)
    elif stats_15m.privilege_changes and stats_15m.event_count >= 5:
        score = max(score, 0.6)
    if stats_5m.location_changes > 1:
        score = max(score, 0.7)
    burst_value = burst if burst is not None else 0.0
    score = max(score, 0.9 * burst_value)
    return round(min(1.0, score), 4)


__all__ = [
    "WINDOW_MINUTES",
    "TemporalTracker",
    "WindowStats",
    "burst_score",
    "temporal_anomaly_score",
    "temporal_vector",
]
