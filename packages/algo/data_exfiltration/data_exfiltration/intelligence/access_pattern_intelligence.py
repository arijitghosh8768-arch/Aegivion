"""Access-pattern intelligence: resources, prefixes, and structural patterns.

Learns/accepts the actor's normal access universe (resources, prefixes,
buckets, databases, tables, data categories, services) and reports
novelty/diversity/spread plus three structural patterns:

- one resource -> many objects
- one bucket  -> many sensitive prefixes
- many resources -> rapid sequential access

Novelty is evidence, not a verdict: a new resource is not automatically
malicious.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.schemas import DataActivityEvent, DataAccessSession, SensitivityLevel

_ONE_RESOURCE_MANY_OBJECTS = 10
_MANY_RESOURCES_RAPID_COUNT = 3
_MANY_RESOURCES_RAPID_SECONDS = 300.0

_NON_SENSITIVE = {None, SensitivityLevel.NONE, SensitivityLevel.PUBLIC}


@dataclass
class KnownAccessUniverse:
    """What this actor/workload normally touches.

    Fields left as ``None`` mean "not supplied": novelty cannot be
    judged for that dimension. An explicit empty set means "supplied,
    nothing known" — everything then counts as novel, which remains
    evidence to review, never a verdict.
    """

    resources: set[str] | None = field(default=None)
    prefixes: set[str] | None = field(default=None)
    buckets: set[str] | None = field(default=None)
    databases: set[str] | None = field(default=None)
    tables: set[str] | None = field(default=None)
    data_categories: set[str] | None = field(default=None)
    services: set[str] | None = field(default=None)


@dataclass
class AccessPatternProfile:
    """Observed access universe accumulated from history."""

    universe: KnownAccessUniverse = field(default_factory=KnownAccessUniverse)
    event_count: int = 0


def object_prefix(object_key: str | None, depth: int = 1) -> str | None:
    """First *depth* path segments of an object key, e.g.
    ``exports/eu/customers.csv`` -> ``exports/`` (depth 1) or
    ``exports/eu/`` (depth 2)."""
    if not object_key:
        return None
    parts = [p for p in object_key.split("/") if p]
    if not parts:
        return None
    return "/".join(parts[:depth]) + "/"


def data_category(event: DataActivityEvent) -> str | None:
    """Coarse data category from storage layout (first prefix segment)."""
    prefix = object_prefix(event.object_key, depth=1)
    if prefix:
        return prefix.rstrip("/")
    if event.database:
        return f"db:{event.database}"
    return None


def build_access_universe(events: Sequence[DataActivityEvent]) -> AccessPatternProfile:
    """Accumulate the observed access universe from historical events."""
    profile = AccessPatternProfile(
        universe=KnownAccessUniverse(
            resources=set(), prefixes=set(), buckets=set(), databases=set(),
            tables=set(), data_categories=set(), services=set(),
        )
    )
    for event in events:
        profile.event_count += 1
        u = profile.universe
        if event.resource_id:
            u.resources.add(event.resource_id)
        if event.bucket:
            u.buckets.add(event.bucket)
        if event.database:
            u.databases.add(event.database)
        if event.table:
            u.tables.add(event.table)
        prefix = object_prefix(event.object_key)
        if prefix:
            u.prefixes.add(f"{event.bucket}:{prefix}")
        category = data_category(event)
        if category:
            u.data_categories.add(category)
        if event.user_agent:
            u.services.add(event.user_agent)
    return profile


def _novelty(values: set[str] | list[str], known: set[str] | None) -> float | None:
    if known is None:
        return None
    if not values:
        return 0.0
    novel = [v for v in values if v not in known]
    return round(len(novel) / len(values), 4)


def access_pattern_signals(
    session: DataAccessSession,
    events: Sequence[DataActivityEvent],
    known: KnownAccessUniverse | None = None,
) -> dict[str, Any]:
    """Compute novelty/diversity/spread signals + structural patterns.

    ``known=None`` (the default) means no access universe was supplied:
    novelty dimensions stay explicitly unavailable instead of scoring a
    silent 100% novelty against a fictitious empty universe.
    """
    known = known or KnownAccessUniverse()

    session_resources = set(session.resources_accessed)
    session_buckets = {r.removeprefix("s3://") for r in session_resources if r.startswith("s3://")}
    session_prefixes: set[str] = set()
    sensitive_prefixes: set[str] = set()
    categories: set[str] = set()
    unique_objects: set[tuple[str | None, str]] = set()

    for event in events:
        if event.event_id not in set(session.event_ids):
            continue
        prefix = object_prefix(event.object_key)
        if prefix and event.bucket:
            session_prefixes.add(f"{event.bucket}:{prefix}")
            if event.sensitivity_level not in _NON_SENSITIVE:
                sensitive_prefixes.add(f"{event.bucket}:{prefix}")
        category = data_category(event)
        if category:
            categories.add(category)
        if event.object_key:
            unique_objects.add((event.bucket, event.object_key))

    signals: dict[str, Any] = {
        "resource_novelty": _novelty(session_resources, known.resources),
        "prefix_novelty": _novelty(session_prefixes, known.prefixes),
        "data_category_novelty": _novelty(categories, known.data_categories),
        "access_diversity": (
            round(len(session_resources) / session.event_count, 4) if session.event_count else None
        ),
        "resource_spread": len(session_buckets) or len(session_resources),
        "unique_objects": len(unique_objects),
        "unique_prefixes": len(session_prefixes),
    }

    duration_s = None
    if session.start_time_epoch_ms is not None and session.end_time_epoch_ms is not None:
        duration_s = (session.end_time_epoch_ms - session.start_time_epoch_ms) / 1000.0

    patterns: dict[str, Any] = {
        "one_resource_many_objects": {
            "detected": bool(len(session_resources) <= 1 and len(unique_objects) >= _ONE_RESOURCE_MANY_OBJECTS),
            "unique_objects": len(unique_objects),
            "threshold": _ONE_RESOURCE_MANY_OBJECTS,
        },
        "one_bucket_many_sensitive_prefixes": {
            "detected": bool(len(session_buckets) <= 1 and len(sensitive_prefixes) >= 2),
            "sensitive_prefixes": sorted(sensitive_prefixes),
        },
        "many_resources_rapid": {
            "detected": bool(
                len(session_resources) >= _MANY_RESOURCES_RAPID_COUNT
                and duration_s is not None
                and duration_s <= _MANY_RESOURCES_RAPID_SECONDS
            ),
            "resources": len(session_resources),
            "duration_seconds": duration_s,
        },
    }
    signals["patterns"] = patterns
    return signals


def access_pattern_score(signals: dict[str, Any]) -> float | None:
    """Max over available novelty components; patterns recorded in detail.

    None when no novelty dimension was computable (no known universe).
    """
    components = [
        signals.get("resource_novelty"),
        signals.get("prefix_novelty"),
        signals.get("data_category_novelty"),
    ]
    available = [c for c in components if c is not None]
    if not available:
        return None
    return max(available)
