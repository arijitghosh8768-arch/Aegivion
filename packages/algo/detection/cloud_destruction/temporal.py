"""Temporal analysis — **Part 2**.

Supports the mandated windows (1-minute / 5-minute / 15-minute /
1-hour / 6-hour / 24-hour) and detects, deterministically:

- **destructive bursts** — a burst window containing
  ``burst_min_events``+ events;
- **slow destruction** — destructive activity spread over
  ``slow_destruction_min_hours``+ with repeated destructive events and
  idle gaps, so volume never spikes in any single burst window;
- **sudden scope expansion** — the post-first-destructive target set
  dwarfing the pre-destructive set;
- **rapid action transitions** — distinct categories in quick succession.

One ``temporal_anomaly`` in ``[0, 1]`` is emitted, plus a per-window
event census in the raw block so every point is explainable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from algo.detection.cloud_destruction.baseline import BehaviorBaseline
from algo.detection.cloud_destruction.config import BehavioralConfig
from algo.detection.cloud_destruction.deviation import clamp01
from algo.detection.cloud_destruction.evidence import SessionEvidence, collect_evidence
from algo.detection.cloud_destruction.provenance import MeasuredValue
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

#: Mandated analysis windows in seconds.
TEMPORAL_WINDOWS_SECONDS: tuple[float, ...] = (
    60.0,
    300.0,
    900.0,
    3600.0,
    21600.0,
    86400.0,
)

__all__ = ["TEMPORAL_WINDOWS_SECONDS", "TemporalAnalysis", "analyze_temporal"]


@dataclass
class TemporalAnalysis:
    """Deterministic temporal features for one session."""

    temporal_anomaly: Optional[MeasuredValue] = None
    burst_detected: bool = False
    slow_destruction_detected: bool = False
    scope_expansion_detected: bool = False
    rapid_transitions_detected: bool = False


def _window_census(times: tuple[datetime, ...]) -> dict[str, int]:
    """For each mandated window, the max events found inside any sliding window."""
    if not times:
        return {f"{int(w)}s": 0 for w in TEMPORAL_WINDOWS_SECONDS}
    ordered = sorted(times)
    census: dict[str, int] = {}
    for window in TEMPORAL_WINDOWS_SECONDS:
        delta = timedelta(seconds=window)
        best = 0
        left = 0
        for right in range(len(ordered)):
            while ordered[right] - ordered[left] > delta:
                left += 1
            best = max(best, right - left + 1)
        census[f"{int(window)}s"] = best
    return census


def _longest_idle_gap(times: tuple[datetime, ...]) -> float:
    if len(times) < 2:
        return 0.0
    ordered = sorted(times)
    return max(
        (b - a).total_seconds() for a, b in zip(ordered, ordered[1:])
    )


def analyze_temporal(
    session: DestructiveActivitySession,
    baseline: Optional[BehaviorBaseline],
    *,
    events: Optional[list[ResourceActivityEvent]] = None,
    config: Optional[BehavioralConfig] = None,
    evidence: Optional[SessionEvidence] = None,
) -> TemporalAnalysis:
    """Analyze temporal shape of one session's destructive activity."""
    cfg = config or BehavioralConfig()
    ev = evidence or collect_evidence(session, events)
    result = TemporalAnalysis()

    destructive_times = ev.destructive_event_times
    if not ev.has_event_detail or not ev.event_times:
        result.temporal_anomaly = MeasuredValue.unavailable(
            "event_detail_missing", contributors=("temporal",)
        )
        return result

    census = _window_census(destructive_times)
    burst = census.get(f"{int(cfg.burst_window_minutes * 60)}s", 0) >= cfg.burst_min_events
    result.burst_detected = burst

    duration_hours = ev.duration_seconds / 3600.0
    slow = (
        len(destructive_times) >= cfg.slow_destruction_splits
        and duration_hours >= cfg.slow_destruction_min_hours
        and _longest_idle_gap(destructive_times) > cfg.burst_window_minutes * 60
    )
    result.slow_destruction_detected = slow

    before = len(ev.resources_before_first_destructive)
    after = len(ev.resources_after_first_destructive)
    scope_expansion = after >= max(2, before * cfg.scope_expansion_factor)
    result.scope_expansion_detected = scope_expansion

    rapid_gap = cfg.rapid_transition_max_gap_seconds
    rapid_transitions = 0

    ordered = sorted(ev.events, key=lambda e: (e.timestamp, e.event_id))
    for prev, nxt in zip(ordered, ordered[1:]):
        gap = (nxt.timestamp - prev.timestamp).total_seconds()
        if gap <= rapid_gap and prev.action_category is not nxt.action_category:
            rapid_transitions += 1
    result.rapid_transitions_detected = rapid_transitions >= cfg.burst_min_events

    score = clamp01(
        (0.35 if burst else 0.0)
        + (0.25 if slow else 0.0)
        + (0.25 if scope_expansion else 0.0)
        + min(0.15, 0.05 * rapid_transitions)
    )
    result.temporal_anomaly = MeasuredValue.measured(
        score,
        method="temporal_shape_indicators",
        contributors=("temporal",),
        raw={
            "window_census_max_events": census,
            "burst_window_minutes": cfg.burst_window_minutes,
            "burst_min_events": cfg.burst_min_events,
            "burst_detected": burst,
            "slow_destruction_detected": slow,
            "duration_hours": duration_hours,
            "scope_expansion_detected": scope_expansion,
            "resources_before_first_destructive": before,
            "resources_after_first_destructive": after,
            "rapid_transitions": rapid_transitions,
        },
    )
    return result
