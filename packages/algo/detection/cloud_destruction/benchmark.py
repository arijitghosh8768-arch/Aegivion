"""Performance benchmarks — **Algorithm #3 final stage**.

Measures, per execution mode:

- **throughput** — events/second;
- **latency** — average and p95 per detector call;
- **CPU** — process CPU seconds consumed by the measured region;
- **memory** — peak Python-heap allocation (``tracemalloc``; no
  third-party dependency is required).

Modes (spec-mandated):

- **batch**      — one ``detect()`` call over the whole stream;
- **streaming**  — the stream arrives in batches; the detector is
                   re-run on the cumulative prefix as each batch
                   lands (true incremental-ingest semantics);
- **replay**     — :class:`~detection.cloud_destruction.replay.ReplayEngine`
                   replay (deterministic, digest-verified).

Batch and replay are repeated ``repeats`` times so the latency
distribution has enough samples for a meaningful p95; a fresh
detector is built per timed run so accumulated audit state never
inflates later runs.
"""

from __future__ import annotations

import time
import tracemalloc
from dataclasses import dataclass
from math import floor
from typing import Any, Optional, Sequence

from detection.cloud_destruction.config import DestructionDetectorConfig
from detection.cloud_destruction.detector import DestructionDetector
from detection.cloud_destruction.replay import ReplayEngine
from detection.cloud_destruction.schemas import ResourceActivityEvent

__all__ = [
    "BenchmarkResult",
    "benchmark_batch",
    "benchmark_replay",
    "benchmark_streaming",
    "run_benchmarks",
]


@dataclass(frozen=True)
class BenchmarkResult:
    """Measured performance of one execution mode."""

    mode: str
    n_events: int
    n_calls: int
    events_processed: int
    events_per_second: float
    avg_latency_ms: float
    p95_latency_ms: float
    cpu_seconds: float
    peak_memory_mb: float

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "n_events": self.n_events,
            "n_calls": self.n_calls,
            "events_processed": self.events_processed,
            "events_per_second": round(self.events_per_second, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 3),
            "p95_latency_ms": round(self.p95_latency_ms, 3),
            "cpu_seconds": round(self.cpu_seconds, 4),
            "peak_memory_mb": round(self.peak_memory_mb, 3),
        }


def _percentile(sorted_values: list[float], q: float) -> float:
    """Linear-interpolated percentile of an ascending list."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = q * (len(sorted_values) - 1)
    lower = floor(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = position - lower
    return sorted_values[lower] + fraction * (
        sorted_values[upper] - sorted_values[lower]
    )


def _run_timed(
    call,
    *,
    n_events: int,
    events_processed: int,
) -> tuple[list[float], float, float, float]:
    """Time ``call()`` under ``tracemalloc``; return (latencies_ms, wall_s, cpu_s, peak_mb)."""
    latencies_ms: list[float] = []
    tracemalloc.start()
    cpu_start = time.process_time()
    wall_start = time.perf_counter()
    try:
        call()
    finally:
        wall = time.perf_counter() - wall_start
        cpu = time.process_time() - cpu_start
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    latencies_ms.append(wall * 1000.0)
    return latencies_ms, wall, cpu, peak_bytes / (1024.0 * 1024.0)


def benchmark_batch(
    events: Sequence[ResourceActivityEvent],
    *,
    config: Optional[DestructionDetectorConfig] = None,
    repeats: int = 3,
) -> BenchmarkResult:
    """Batch mode: one detect() call over the entire stream."""
    events = list(events)
    latencies_ms: list[float] = []
    walls: list[float] = []
    cpu_seconds = 0.0
    peak_mb = 0.0

    for _ in range(max(1, repeats)):
        detector = DestructionDetector(config)

        def _call(detector=detector, events=events):  # noqa: B023
            detector.detect(events)

        sample, wall, cpu, peak = _run_timed(
            _call, n_events=len(events), events_processed=len(events)
        )
        latencies_ms.extend(sample)
        walls.append(wall)
        cpu_seconds += cpu
        peak_mb = max(peak_mb, peak)

    total_wall = sum(walls)
    runs = max(1, repeats)
    processed = len(events) * runs
    return BenchmarkResult(
        mode="batch",
        n_events=len(events),
        n_calls=runs,
        events_processed=processed,
        events_per_second=(processed / total_wall) if total_wall > 0 else 0.0,
        avg_latency_ms=(
            sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
        ),
        p95_latency_ms=_percentile(sorted(latencies_ms), 0.95),
        cpu_seconds=cpu_seconds,
        peak_memory_mb=peak_mb,
    )


def benchmark_streaming(
    events: Sequence[ResourceActivityEvent],
    *,
    config: Optional[DestructionDetectorConfig] = None,
    batch_size: int = 50,
) -> BenchmarkResult:
    """Streaming mode: cumulative re-detection as each batch lands."""
    ordered = sorted(events, key=lambda event: event.timestamp)
    detector = DestructionDetector(config)
    latencies_ms: list[float] = []
    processed = 0

    tracemalloc.start()
    cpu_start = time.process_time()
    wall_start = time.perf_counter()
    try:
        for end in range(batch_size, len(ordered) + batch_size, batch_size):
            prefix = ordered[: min(end, len(ordered))]
            if not prefix:
                break
            batch_start = time.perf_counter()
            detector.detect(prefix)
            latencies_ms.append((time.perf_counter() - batch_start) * 1000.0)
            processed += len(prefix)
    finally:
        wall = time.perf_counter() - wall_start
        cpu = time.process_time() - cpu_start
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    calls = len(latencies_ms)
    return BenchmarkResult(
        mode="streaming",
        n_events=len(ordered),
        n_calls=calls,
        events_processed=processed,
        events_per_second=(processed / wall) if wall > 0 else 0.0,
        avg_latency_ms=(
            sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
        ),
        p95_latency_ms=_percentile(sorted(latencies_ms), 0.95),
        cpu_seconds=cpu,
        peak_memory_mb=peak_bytes / (1024.0 * 1024.0),
    )


def benchmark_replay(
    events: Sequence[ResourceActivityEvent],
    *,
    config: Optional[DestructionDetectorConfig] = None,
    repeats: int = 3,
) -> BenchmarkResult:
    """Replay mode: deterministic replay through the ReplayEngine."""
    events = list(events)
    latencies_ms: list[float] = []
    walls: list[float] = []
    cpu_seconds = 0.0
    peak_mb = 0.0

    for _ in range(max(1, repeats)):
        engine = ReplayEngine(config, replay_source="benchmark")

        def _call(engine=engine, events=events):  # noqa: B023
            engine.run(events)

        sample, wall, cpu, peak = _run_timed(
            _call, n_events=len(events), events_processed=len(events)
        )
        latencies_ms.extend(sample)
        walls.append(wall)
        cpu_seconds += cpu
        peak_mb = max(peak_mb, peak)

    total_wall = sum(walls)
    runs = max(1, repeats)
    processed = len(events) * runs
    return BenchmarkResult(
        mode="replay",
        n_events=len(events),
        n_calls=runs,
        events_processed=processed,
        events_per_second=(processed / total_wall) if total_wall > 0 else 0.0,
        avg_latency_ms=(
            sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
        ),
        p95_latency_ms=_percentile(sorted(latencies_ms), 0.95),
        cpu_seconds=cpu_seconds,
        peak_memory_mb=peak_mb,
    )


def run_benchmarks(
    events: Sequence[ResourceActivityEvent],
    *,
    config: Optional[DestructionDetectorConfig] = None,
    batch_repeats: int = 3,
    replay_repeats: int = 3,
    streaming_batch_size: int = 50,
) -> dict[str, BenchmarkResult]:
    """Run all three spec-mandated execution modes."""
    return {
        "batch": benchmark_batch(
            events, config=config, repeats=batch_repeats
        ),
        "streaming": benchmark_streaming(
            events, config=config, batch_size=streaming_batch_size
        ),
        "replay": benchmark_replay(
            events, config=config, repeats=replay_repeats
        ),
    }
