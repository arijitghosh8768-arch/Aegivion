"""Behavioral baselines: descriptive statistics over session histories.

A baseline is an immutable, versioned snapshot of what sessions have
historically looked like for one resource (or globally). Part 1 computes
descriptive statistics only — medians, p95, totals. It does NOT decide
what counts as anomalous; that is Part 2 risk-fusion territory.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from algo.data_exfiltration.data_exfiltration.schemas import (
    BaselineComponent,
    DataAccessSession,
    DataBaselineVersion,
)

_DETERMINISTIC_SALT = "aegivion-baseline-v1"


def _stable_version_id() -> str:
    digest_source = f"{_DETERMINISTIC_SALT}:{_utcnow_ms()}"
    import hashlib

    return "bl-" + hashlib.sha256(digest_source.encode()).hexdigest()[:12]


def compute_baseline(
    sessions: Sequence[DataAccessSession],
    *,
    baseline_id: str | None = None,
) -> DataBaselineVersion:
    """Compute a descriptive baseline over *sessions*.

    Components (all descriptive; none constitute a risk judgment):
    - duration_p50_s / duration_p95_s
    - bytes_total_p50 / bytes_total_p95   (max-confidence category)
    - egress_bytes_p50 / egress_bytes_p95
    - event_count_p50 / event_count_p95
    - request_count_p50 / request_count_p95
    - distinct_resources_p50
    - destinations_p50 / destinations_p95
    - sensitive_session_share
    """
    if not sessions:
        return DataBaselineVersion(
            version_id=baseline_id or _stable_version_id(),
            created_at_epoch_ms=_utcnow_ms(),
            session_count=0,
            components={},
        )

    durations = _durations(sessions)
    bytes_totals = [_primary_bytes(s.bytes_accessed) for s in sessions]
    egress_totals = [_primary_bytes(s.network_egress_bytes) for s in sessions]
    event_counts = [float(s.event_count) for s in sessions]
    request_counts = [float(s.request_count) for s in sessions]
    distinct_resources = [float(len(s.resources_accessed)) for s in sessions]
    destinations = [float(len(s.unique_destinations)) for s in sessions]
    sensitive_flags = [1.0 if _is_sensitive_session(s) else 0.0 for s in sessions]

    components: dict[str, BaselineComponent] = {}

    def add(name: str, values: list[float], skip_missing: bool = True) -> None:
        usable = [v for v in values if v is not None]
        if not usable:
            return
        components[name] = BaselineComponent(
            name=name,
            value=_percentile(usable, 50),
            sample_count=len(usable),
            method="p50",
        )
        components[name.replace("_p50", "_p95")] = BaselineComponent(
            name=name.replace("_p50", "_p95"),
            value=_percentile(usable, 95),
            sample_count=len(usable),
            method="p95",
        )

    add("duration_p50_s", durations)
    add("bytes_total_p50", [v for v in bytes_totals if v is not None])
    add("egress_bytes_p50", [v for v in egress_totals if v is not None])
    add("event_count_p50", event_counts)
    add("request_count_p50", request_counts)
    add("distinct_resources_p50", distinct_resources)
    add("destinations_p50", destinations)

    if sensitive_flags:
        share = sum(sensitive_flags) / len(sensitive_flags)
        components["sensitive_session_share"] = BaselineComponent(
            name="sensitive_session_share",
            value=share,
            sample_count=len(sensitive_flags),
            method="mean",
        )

    return DataBaselineVersion(
        version_id=baseline_id or _stable_version_id(),
        created_at_epoch_ms=_utcnow_ms(),
        session_count=len(sessions),
        components=components,
    )


def baseline_summary(baseline: DataBaselineVersion) -> dict[str, Any]:
    """Human-readable summary of baseline components."""
    return {
        "version_id": baseline.version_id,
        "session_count": baseline.session_count,
        "components": {
            name: {"value": comp.value, "samples": comp.sample_count, "method": comp.method}
            for name, comp in sorted(baseline.components.items())
        },
    }


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def _durations(sessions: Sequence[DataAccessSession]) -> list[float]:
    out = []
    for session in sessions:
        if session.start_time_epoch_ms is None or session.end_time_epoch_ms is None:
            continue
        out.append((session.end_time_epoch_ms - session.start_time_epoch_ms) / 1000.0)
    return out


def _primary_bytes(measurement) -> float | None:
    """Primary value from a session aggregate (max across categories).

    Conservative: uses the largest per-source category sum.
    """
    if measurement is None or not measurement.measurements:
        return None
    return max(m.value for m in measurement.measurements)


def _is_sensitive_session(session: DataAccessSession) -> bool:
    summary = session.sensitivity_summary
    if summary is None or summary.measurement is None:
        return False
    return any(m.value >= 0.5 for m in summary.measurement.measurements)


def _percentile(values: Sequence[float], pct: float) -> float:
    """Linear-interpolated percentile (numpy-compatible for p50/p95)."""
    if not values:
        raise ValueError("percentile of empty sequence")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    k = (len(ordered) - 1) * (pct / 100.0)
    low = int(k)
    high = min(low + 1, len(ordered) - 1)
    frac = k - low
    return float(ordered[low] + (ordered[high] - ordered[low]) * frac)


def _utcnow_ms() -> float:
    return datetime.now(timezone.utc).timestamp() * 1000.0
