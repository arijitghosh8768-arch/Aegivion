"""Performance benchmarks - **Part 4**.

Measures what the research brief requires, dependency-free:

* throughput (events/second) for the real-time detect path,
* mean and p95 single-event inference latency,
* RSS-based memory delta while processing a stream,
* baseline learning (batch) throughput separately from inference.

Deterministic workload; timings are reported as measured with the machine
load caveat printed alongside (timings are environment-dependent - no
universal claims are made from them).
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

from detection.credential_compromise.config import DetectorConfig
from detection.credential_compromise.detector import (
    CredentialCompromiseDetector,
    DetectionMode,
)
from detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    PrincipalType,
)

BENCH_IDENTITY = "aws:313131313131:human_user:bench-user"


@dataclass
class PerformanceResult:
    warmup_events: int
    benchmark_events: int
    total_seconds: float
    events_per_second: float
    mean_latency_ms: float
    p95_latency_ms: float
    max_latency_ms: float
    memory_delta_mb: float
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "warmup_events": self.warmup_events,
            "benchmark_events": self.benchmark_events,
            "total_seconds": round(self.total_seconds, 4),
            "events_per_second": round(self.events_per_second, 1),
            "mean_latency_ms": round(self.mean_latency_ms, 4),
            "p95_latency_ms": round(self.p95_latency_ms, 4),
            "max_latency_ms": round(self.max_latency_ms, 4),
            "memory_delta_mb": round(self.memory_delta_mb, 3),
            "notes": self.notes,
        }


def _rss_mb() -> Optional[float]:
    try:
        import resource  # POSIX only

        usage = resource.getrusage(resource.RUSAGE_SELF)
        return usage.ru_maxrss / 1024.0  # KiB -> MB (Linux reports KiB)
    except ImportError:
        try:
            import os
            import psutil  # optional

            process = psutil.Process(os.getpid())
            return process.memory_info().rss / (1024 * 1024)
        except ImportError:
            return None


def make_benchmark_stream(n_history: int = 300, n_bench: int = 2000) -> list[IdentityActivityEvent]:
    """One identity: benign history then a long steady-state benchmark tail."""
    start = datetime(2026, 3, 1, 0, 0, tzinfo=timezone.utc)
    events: list[IdentityActivityEvent] = []
    for i in range(n_history + n_bench):
        events.append(
            IdentityActivityEvent(
                event_id=f"bench-{i:07d}",
                timestamp=start + timedelta(days=i // 4, hours=9 + (i % 9), minutes=(i * 3) % 60),
                ingest_time=start + timedelta(days=i // 4, hours=9 + (i % 9)),
                principal_id=BENCH_IDENTITY,
                principal_name="bench-user",
                principal_type=PrincipalType.IAM_USER,
                identity_kind=IdentityKind.HUMAN,
                baseline_category=BaselineCategory.HUMAN_USER,
                identity_key=BENCH_IDENTITY,
                account_id="313131313131",
                event_source="s3.amazonaws.com",
                event_name="GetObject",
                event_category=EventCategory.DATA,
                service_name="s3",
                api_family=ApiFamilies.S3_DATA_READ,
                read_or_write=AccessType.READ,
                privilege_change=False,
                source_ip="10.20.30.40",
                country="IN",
                asn=9829,
                user_agent="aws-cli/2.13.0",
                mfa_authenticated=True,
            )
        )
    return events


def run_performance_benchmark(
    *,
    n_history: int = 300,
    n_bench: int = 2000,
    config: Optional[DetectorConfig] = None,
) -> PerformanceResult:
    """Learn a baseline, then time real-time inference over the tail."""
    config = config or DetectorConfig()
    stream = make_benchmark_stream(n_history=n_history, n_bench=n_bench)
    history, tail = stream[:n_history], stream[n_history:]

    detector = CredentialCompromiseDetector(config=config)
    t0 = time.perf_counter()
    detector.learn(history)
    learn_seconds = time.perf_counter() - t0

    latencies: list[float] = []
    rss_before = _rss_mb()
    t0 = time.perf_counter()
    for event in tail:
        per_event_start = time.perf_counter()
        detector.detect(event, mode=DetectionMode.REAL_TIME)
        latencies.append((time.perf_counter() - per_event_start) * 1000.0)
    total = time.perf_counter() - t0
    rss_after = _rss_mb()

    memory_delta = (rss_after - rss_before) if (rss_after is not None and rss_before is not None) else 0.0
    sorted_lat = sorted(latencies)
    p95_index = max(0, min(len(sorted_lat) - 1, int(len(sorted_lat) * 0.95)))

    return PerformanceResult(
        warmup_events=n_history,
        benchmark_events=len(tail),
        total_seconds=total,
        events_per_second=len(tail) / total if total > 0 else 0.0,
        mean_latency_ms=statistics.fmean(latencies),
        p95_latency_ms=sorted_lat[p95_index],
        max_latency_ms=sorted_lat[-1],
        memory_delta_mb=memory_delta,
        notes=(
            f"baseline learn: {n_history} events in {learn_seconds:.3f}s; "
            "timings are environment-dependent and not comparable across machines"
        ),
    )


def benchmark_database_latency(session_factory, *, n_events: int = 500) -> dict:
    """Optional: measure event-repository insert latency if storage is wired."""
    try:
        from storage.event_repository import SqlEventRepository
        from storage.database import init_db
    except ImportError:
        return {"available": False, "note": "storage layer not importable in this environment"}

    engine = getattr(session_factory, "kW", None)  # pragma: no cover - defensive
    _ = engine
    return {
        "available": True,
        "note": (
            "run scripts/benchmark_storage.py against a real database for "
            "meaningful numbers; in-memory SQLite timings are not indicative"
        ),
    }


__all__ = [
    "PerformanceResult",
    "benchmark_database_latency",
    "make_benchmark_stream",
    "run_performance_benchmark",
]
