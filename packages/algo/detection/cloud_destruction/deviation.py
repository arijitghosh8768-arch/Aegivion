"""Shared deterministic deviation math for the Part 2 analyzers.

Deviation semantics used across every analyzer (documented contract):

- ``0.0``  → at or below normal;
- ``1.0``  → at or above the configured factor over normal;
- linear in between; clamped to ``[0, 1]``;
- ``None`` → no baseline evidence (callers record unavailability, never 0).

No ML, no learned weights — pure functions of the evidence.
"""

from __future__ import annotations

from typing import Optional

from algo.detection.cloud_destruction.provenance import MeasuredValue


def clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def ratio_to_factor(
    value: float,
    normal: Optional[float],
    factor: float,
    *,
    floor: float = 0.0,
) -> Optional[float]:
    """Normalize ``value`` against ``normal`` to ``[0, 1]`` by ``factor``.

    - ``normal is None`` → ``None`` (no baseline evidence).
    - ``value <= max(normal, floor)`` → ``0.0``.
    - otherwise linear ramp to 1.0 at ``normal * factor``.
    """
    if normal is None:
        return None
    reference = max(normal, floor)
    if reference <= 0.0:
        # Normal is zero (or unusable): any positive value is "above normal"
        # and cannot be scaled by a factor — report the full-deviation rung
        # only when the value itself is clearly positive.
        return clamp01(value) if value > 0 else 0.0
    if value <= reference:
        return 0.0
    return clamp01((value - reference) / (reference * (factor - 1.0)))


def rate_deviation_value(
    *,
    observed: float,
    normal_mean: Optional[float],
    factor: float,
    method: str,
    contributors: tuple[str, ...],
    raw: dict[str, object],
) -> MeasuredValue:
    """Build a ``MeasuredValue`` for a rate deviation feature."""
    deviation = ratio_to_factor(observed, normal_mean, factor, floor=0.0)
    if deviation is None:
        return MeasuredValue.unavailable("no_baseline", contributors=contributors)
    return MeasuredValue.measured(
        deviation,
        method=method,
        contributors=contributors,
        raw=raw,
    )


def absolute_pace_value(
    *,
    observed_per_hour: float,
    cap_per_hour: float,
    method: str,
    contributors: tuple[str, ...],
    raw: dict[str, object],
) -> MeasuredValue:
    """Pace-based fallback value (used when no baseline exists).

    Maps an absolute observed pace to ``[0, 1]`` against an explicitly
    configured evidence cap. This is *not* a baseline deviation — the raw
    counters always accompany it so Part 3 can weight it accordingly.
    """
    return MeasuredValue.measured(
        clamp01(observed_per_hour / cap_per_hour if cap_per_hour > 0 else 0.0),
        method=method,
        contributors=contributors,
        raw=raw,
    )


def hour_span(evidence_count: int, duration_seconds: float, floor_seconds: float) -> float:
    """Duration in hours with a floor so single-burst sessions are rate-safe."""
    return max(duration_seconds, floor_seconds) / 3600.0


__all__ = [
    "absolute_pace_value",
    "clamp01",
    "hour_span",
    "rate_deviation_value",
    "ratio_to_factor",
]
