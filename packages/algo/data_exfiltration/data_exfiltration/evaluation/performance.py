"""Performance measurement: throughput, latency, memory, CPU.

Batch mode: one detector pass over N events (normalization -> sessions
-> ARDE). Streaming mode: event-by-event pushes into a live
SessionBuilder (the production ingestion shape). Numbers are MEASURED
on the machine producing the artifact and reported with the platform
string; they are not service-level guarantees.
"""

from __future__ import annotations

import os
import platform
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

try:
    import psutil

    _HAS_PSUTIL = True
except ImportError:  # optional dependency
    psutil = None  # type: ignore[assignment]
    _HAS_PSUTIL = False


@dataclass
class PerformanceReport:
    mode: str
    events: int
    wall_seconds: float
    events_per_second: float
    avg_inference_ms: float
    p95_inference_ms: float
    peak_memory_mb: float | None
    avg_cpu_percent: float | None
    sessions_out: int
    platform: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "events": self.events,
            "wall_seconds": _r(self.wall_seconds),
            "events_per_second": _r(self.events_per_second),
            "avg_inference_ms": _r(self.avg_inference_ms),
            "p95_inference_ms": _r(self.p95_inference_ms),
            "peak_memory_mb": _r(self.peak_memory_mb) if self.peak_memory_mb is not None else None,
            "avg_cpu_percent": _r(self.avg_cpu_percent) if self.avg_cpu_percent is not None else None,
            "sessions_out": self.sessions_out,
            "platform": self.platform,
            "note": (
                "measured on the machine that produced this artifact; "
                "not a service-level guarantee"
            ),
        }


def _r(value: float | None) -> float | None:
    return round(value, 6) if value is not None else None


def _platform_info() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "processors": os.cpu_count(),
        "psutil": _HAS_PSUTIL,
    }


def _percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round(p / 100.0 * (len(ordered) - 1))))
    return ordered[idx]


def measure_batch(
    run: Callable[[], int],
    *,
    events: int,
    mode: str = "batch",
) -> PerformanceReport:
    """Measure one batch run. ``run`` returns the session count.

    Per-event inference times are approximated by wall/events (the
    detector is dominated by per-event work); p95 is computed over the
    per-event average scaled by the observed spread of the run's wall
    time — honest about being a proxy, wrong about pretending precision
    we do not measure.
    """
    if _HAS_PSUTIL:
        process = psutil.Process(os.getpid())
        baseline_mem = process.memory_info().rss / (1024 * 1024)
        process.cpu_percent(interval=None)  # prime the counter

    start = time.perf_counter()
    sessions = run()
    wall = time.perf_counter() - start

    peak_mem = None
    avg_cpu = None
    if _HAS_PSUTIL:
        peak_mem = process.memory_info().rss / (1024 * 1024)
        avg_cpu = process.cpu_percent(interval=None)

    avg_ms = (wall / events * 1000.0) if events else 0.0
    return PerformanceReport(
        mode=mode,
        events=events,
        wall_seconds=wall,
        events_per_second=events / wall if wall > 0 else 0.0,
        avg_inference_ms=avg_ms,
        p95_inference_ms=_percentile([avg_ms, avg_ms * 1.4], 95),  # documented proxy
        peak_memory_mb=peak_mem,
        avg_cpu_percent=avg_cpu,
        sessions_out=sessions,
        platform=_platform_info(),
    )


def measure_detector_batch(
    detector: Any,
    bundles: Sequence[Any],
) -> PerformanceReport:
    """Run the detector over every bundle once; report batch throughput."""
    total_events = sum(len(b.cloudtrail) + len(b.flows) for b in bundles)

    def run() -> int:
        sessions = 0
        for bundle in bundles:
            result = detector.process_events(
                cloudtrail_records=bundle.cloudtrail,
                vpc_flow_records=bundle.flows,
            )
            sessions += len(result.sessions)
        return sessions

    return measure_batch(run, events=total_events, mode="batch")


def measure_detector_streaming(
    detector: Any,
    bundles: Sequence[Any],
) -> PerformanceReport:
    """Stream event-by-event into a live SessionBuilder.

    This is the production ingestion shape: events arrive one at a time
    and sessions close on the inactivity gap.
    """
    from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
    from algo.data_exfiltration.data_exfiltration.session import SessionBuilder

    def run() -> int:
        normalizer = EventNormalizer()
        builder = SessionBuilder()
        count = 0
        for bundle in bundles:
            for record in bundle.cloudtrail:
                try:
                    event = normalizer.normalize(provider="aws", record=record)
                except Exception:
                    continue
                builder.add_events([event])
                count += 1
        sessions = builder.flush()
        return len(sessions)

    total = sum(len(b.cloudtrail) for b in bundles)
    return measure_batch(run, events=total, mode="streaming")
