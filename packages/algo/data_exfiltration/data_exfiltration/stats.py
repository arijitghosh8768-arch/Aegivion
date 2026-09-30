"""Robust statistics primitives for behavioral baselines.

Part 2 deliberately avoids depending on mean/standard deviation for
deviation math: small samples and outlier-heavy telemetry make them
fragile. We use median / percentiles / MAD (median absolute deviation)
and modified z-scores (Iglewicz-Hoaglin), with mean+std used only as a
documented fallback when MAD is degenerate.
"""

from __future__ import annotations

import math
from typing import Iterable, Sequence

# Classical consistency constant for normally distributed data.
_MAD_SCALE = 1.4826
_EPSILON = 1e-12


def median(values: Iterable[float]) -> float | None:
    vals = sorted(values)
    if not vals:
        return None
    n = len(vals)
    mid = n // 2
    if n % 2:
        return float(vals[mid])
    return (vals[mid - 1] + vals[mid]) / 2.0


def percentile(values: Sequence[float], pct: float) -> float | None:
    """Linear-interpolated percentile; None for empty input."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    k = (len(ordered) - 1) * (pct / 100.0)
    low = int(k)
    high = min(low + 1, len(ordered) - 1)
    frac = k - low
    return float(ordered[low] + (ordered[high] - ordered[low]) * frac)


def mad(values: Sequence[float]) -> float | None:
    """Median absolute deviation; None when empty."""
    med = median(values)
    if med is None:
        return None
    return median([abs(v - med) for v in values])


def modified_z_scores(values: Sequence[float]) -> list[float] | None:
    """Modified z-scores: 0.6745 * (x - median) / MAD.

    Falls back to classical z-scores when MAD is degenerate (zero), which
    happens when >50% of observations are identical.
    """
    med = median(values)
    if med is None:
        return None
    m = mad(values)
    if m is None or m < _EPSILON:
        # degenerate MAD: fall back to std-based z, or zeros for tiny samples
        n = len(values)
        if n < 2:
            return [0.0 for _ in values]
        var = sum((v - med) ** 2 for v in values) / (n - 1)
        std = math.sqrt(var)
        if std < _EPSILON:
            return [0.0 for _ in values]
        return [(v - med) / std for v in values]
    return [0.6745 * (v - med) / (m * _MAD_SCALE) if m > _EPSILON else 0.0 for v in values]


def deviation_score(observed: float, history: Sequence[float], gate: float = 3.5) -> float:
    """0..1 deviation of *observed* from robust history.

    - reference distribution is the HISTORY ONLY (the observation being
      judged never inflates its own baseline)
    - ONE-SIDED: only upward deviation counts. For data-movement metrics,
      being below typical is never exfiltration-relevant; the score
      measures "unusually LARGE", not "different in any direction"
    - modified z-score gated at *gate* (default 3.5, Iglewicz-Hoaglin)
    - degenerate MAD (zero) falls back to history std; a constant history
      makes any upward difference maximally deviant
    - cold-start/absence of history returns 0.0 — absence of history is
      NOT deviation (never classify as suspicious for having no history)
    - monotone piecewise ramp: gate -> 0.0, 2x gate -> 1.0
    """
    if not history:
        return 0.0
    med = median(history)
    if med is None:
        return 0.0
    if observed <= med:
        return 0.0  # below typical: not a volume-style deviation
    m = mad(history)
    if m is not None and m > _EPSILON:
        z = 0.6745 * (observed - med) / (m * _MAD_SCALE)
    else:
        n = len(history)
        std = 0.0
        if n >= 2:
            var = sum((v - med) ** 2 for v in history) / (n - 1)
            std = math.sqrt(var)
        if std > _EPSILON:
            z = (observed - med) / std
        else:
            # constant history: identical observation is not deviant,
            # any material difference is maximally deviant
            return 0.0 if abs(observed - med) <= _EPSILON else 1.0
    if z <= gate:
        return 0.0
    return min(1.0, (z - gate) / gate)


def ratio_log_growth(observed: float, typical: float) -> float:
    """0..1 growth of *observed* vs *typical* using log2 ratio.

    1x -> 0.0, 2x -> ~0.39, 4x -> ~0.79, 8x+ -> 1.0.
    Typical <= 0 yields 0.0 (nothing to compare against).
    """
    if typical <= _EPSILON:
        return 0.0
    if observed <= 0:
        return 0.0
    growth = observed / typical
    if growth <= 1.0:
        return 0.0
    return min(1.0, math.log2(growth) / 3.0)


def weighted_mean(values: Sequence[float], weights: Sequence[float]) -> float | None:
    """Weighted mean; None when no values or weights sum to ~0."""
    if not values or len(values) != len(weights):
        return None
    total_w = sum(weights)
    if total_w <= _EPSILON:
        return None
    return sum(v * w for v, w in zip(values, weights)) / total_w


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))
