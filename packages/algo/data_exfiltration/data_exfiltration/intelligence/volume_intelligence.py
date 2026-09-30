"""Volume intelligence: multi-window robust deviation analysis.

For each scope (actor / workload / resource) we aggregate bytes, objects,
requests, unique resources, and unique objects over the six standard
windows (5m/15m/1h/6h/24h/7d) and compare each window against the
entity's trusted history using robust statistics (median/MAD modified
z-scores). Byte categories (observed vs estimated) are aggregated
separately throughout — the conservative per-category maximum is the
primary value.

An absence of history yields score None (unavailable), never suspicion.
"""

from __future__ import annotations

from typing import Any, Sequence

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.config import WindowConfig
from algo.data_exfiltration.data_exfiltration.stats import deviation_score
from algo.data_exfiltration.data_exfiltration.windows import (
    ScopeKeyFn,
    WindowAggregate,
    aggregate_window,
)
from algo.data_exfiltration.data_exfiltration.schemas import DataActivityEvent

from .baseline_engine import BaselineEngine, BaselineSnapshot, Scope


class WindowSignals(BaseModel):
    """Raw window aggregates for one scope key."""

    window_seconds: float
    event_count: int = 0
    bytes_by_confidence: dict[str, float] = Field(default_factory=dict)
    bytes_primary: float = 0.0
    objects: int = 0
    requests: int = 0
    unique_resources: int = 0
    unique_objects: int = 0


class VolumeDeviations(BaseModel):
    """Per-window deviation results plus the cross-window maxima."""

    windows: dict[str, Any] = Field(default_factory=dict)
    """window label -> {scores..., baseline info}"""
    volume_deviation: float | None = None
    object_count_deviation: float | None = None
    request_rate_deviation: float | None = None
    resource_diversity_deviation: float | None = None
    baseline_source: str = "none"
    baseline_quality: float = 0.0
    detail: dict[str, Any] = Field(default_factory=dict)


def compute_window_signals(
    events: Sequence[DataActivityEvent],
    *,
    scope_fn: ScopeKeyFn,
    scope_key: str,
    windows: Sequence[float],
    end_epoch_ms: float,
) -> dict[float, WindowSignals]:
    """Aggregate *events* for one scope key over each window size."""
    out: dict[float, WindowSignals] = {}
    for window in windows:
        aggs = aggregate_window(
            events,
            scope_fn=scope_fn,
            window_seconds=window,
            end_epoch_ms=end_epoch_ms,
            scope_key=scope_key,
        )
        agg: WindowAggregate | None = aggs.get(scope_key)
        if agg is None:
            out[window] = WindowSignals(window_seconds=window)
            continue
        out[window] = WindowSignals(
            window_seconds=window,
            event_count=agg.event_count,
            bytes_by_confidence=agg.bytes_by_confidence,
            bytes_primary=agg.max_bytes,
            objects=agg.objects_accessed,
            requests=agg.request_count,
            unique_resources=len(agg.unique_resources),
            unique_objects=len(agg.unique_objects),
        )
    return out


_WINDOW_METRICS = (
    # (window label, metric name in the engine, signal attribute)
    ("bytes", "bytes_primary"),
    ("objects", "objects"),
    ("requests", "requests"),
    ("resources", "unique_resources"),
)


def volume_deviations(
    events: Sequence[DataActivityEvent],
    engine: BaselineEngine,
    *,
    scope: Scope,
    scope_fn: ScopeKeyFn,
    scope_key: str,
    end_epoch_ms: float,
    peer_group: str | None = None,
    windows: Sequence[float] | None = None,
) -> VolumeDeviations:
    """Robust per-window deviations against the baseline engine.

    Per window each metric is compared with the entity's trusted history
    (personal first, then peer group when supplied). Windows with no
    activity produce unavailable components, not zeros.
    """
    cfg_windows = windows or WindowConfig().window_sizes_seconds
    signals = compute_window_signals(
        events, scope_fn=scope_fn, scope_key=scope_key, windows=cfg_windows, end_epoch_ms=end_epoch_ms
    )

    result = VolumeDeviations()
    maxima: dict[str, float] = {}
    sources: set[str] = set()

    for window in cfg_windows:
        sig = signals[window]
        label = _label(window)
        entry: dict[str, Any] = {
            "window": label,
            "event_count": sig.event_count,
            "bytes_primary": sig.bytes_primary,
            "bytes_by_confidence": sig.bytes_by_confidence,
            "objects": sig.objects,
            "requests": sig.requests,
            "unique_resources": sig.unique_resources,
            "unique_objects": sig.unique_objects,
        }
        if sig.event_count == 0:
            entry["status"] = "inactive_window"
            result.windows[label] = entry
            continue

        for metric_name, attr in _WINDOW_METRICS:
            observed = float(getattr(sig, attr))
            score, snap = engine.deviation(
                scope, metric_name, scope_key, observed,
                end_epoch_ms=end_epoch_ms, peer_group=peer_group,
            )
            key = {
                "bytes": "volume_deviation",
                "objects": "object_count_deviation",
                "requests": "request_rate_deviation",
                "resources": "resource_diversity_deviation",
            }[metric_name]
            entry[f"{metric_name}_deviation"] = score
            if snap is not None:
                entry[f"{metric_name}_baseline"] = snap.as_dict()
                sources.add(snap.source)
                result.baseline_quality = max(result.baseline_quality, snap.baseline_quality)
            else:
                entry[f"{metric_name}_baseline"] = None
            if snap is not None:
                # deviations from cold-start fallbacks still carry evidence,
                # but personal warm history wins the cross-window maximum
                maxima[key] = max(maxima.get(key, 0.0), score)

        result.windows[label] = entry

    if maxima:
        result.volume_deviation = maxima.get("volume_deviation", 0.0)
        result.object_count_deviation = maxima.get("object_count_deviation", 0.0)
        result.request_rate_deviation = maxima.get("request_rate_deviation", 0.0)
        result.resource_diversity_deviation = maxima.get("resource_diversity_deviation", 0.0)

    result.baseline_source = (
        "personal" if "personal" in sources else "peer" if "peer" in sources else "none"
    )
    result.detail = {
        "scope": scope,
        "scope_key": scope_key,
        "windows_evaluated": [w for w in cfg_windows],
    }
    return result


def _label(window_seconds: float) -> str:
    return {
        300.0: "5m",
        900.0: "15m",
        3600.0: "1h",
        21600.0: "6h",
        86400.0: "24h",
        604800.0: "7d",
    }.get(window_seconds, f"{int(window_seconds)}s")
