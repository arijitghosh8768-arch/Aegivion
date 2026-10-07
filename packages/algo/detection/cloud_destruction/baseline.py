"""Behavioral baselines for destructive activity — **Part 2**.

Derives per-actor "what normal looks like" from session history: normal
write/modify/delete/rewrite rates, normal resource scope, normal operations,
normal change windows — with an explicit :class:`BaselineQuality` and
**baseline poisoning defense**.

Baseline poisoning defense (core Part 2 rule — never learn attacks):

- A historical session's *contamination* is classified from its own evidence
  counters (never from any score): protection changes, version deletions,
  recovery-impairing deletions, destructive ratio and volume.
- ``LOW``      → fully eligible for learning.
- ``MEDIUM``   → limited influence (fractional learning weight).
- ``HIGH``     → excluded from the trusted baseline.
- ``CRITICAL`` → never automatically learned.
- Approval via an :class:`ApprovedActivityProfile` restores full learning
  weight only at the LOW/MEDIUM rungs — HIGH/CRITICAL sessions are never
  rehabilitated automatically.
- Baselines are **versioned**: every build is stamped with a generation and
  a content-derived ``baseline_version``; :class:`BaselineStore` retains
  prior generations so drift is auditable.

Per the Part 2 mandate there is **no ML**: statistics are deterministic
weighted means and mean absolute deviations. History comes from Part 1
session aggregates (always available) plus optional per-session events
(refines normal resource types / operations). ``InsufficientHistoryError``
is raised only by :meth:`BehaviorBaseline.require` —
:meth:`BaselineStore.get_or_build` returns ``None`` instead so callers can
record feature unavailability honestly.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Sequence

# typing note: selectors receive the per-session counts dict from
# ``_event_counts`` / ``_aggregate_counts``.

from algo.detection.cloud_destruction.config import BaselineConfig
from algo.detection.cloud_destruction.exceptions import InsufficientHistoryError
from algo.detection.cloud_destruction.legitimate import ApprovedActivityProfile, match_profile
from algo.detection.cloud_destruction.provenance import MeasuredValue
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

#: Deletion-family categories for baseline counting (mirrors evidence.py).
DELETION_FAMILY_CATEGORIES = frozenset(
    {
        ActionCategory.DELETE,
        ActionCategory.VERSION_DELETE,
        ActionCategory.SNAPSHOT_DELETE,
        ActionCategory.BACKUP_DELETE,
        ActionCategory.RECOVERY_POINT_DELETE,
    }
)

__all__ = [
    "ActorNovelty",
    "BaselineContamination",
    "BaselineQuality",
    "BaselineStore",
    "BehaviorBaseline",
    "LEARNING_WEIGHT",
    "classify_contamination",
    "build_baseline",
    "measure_novelty",
]


class BaselineQuality(str, Enum):
    """How much trust a baseline deserves (reported on every feature vector)."""

    GOOD = "good"
    LIMITED = "limited"
    INSUFFICIENT = "insufficient"
    NONE = "none"


class BaselineContamination(str, Enum):
    """Poisoning-defense classification of one historical session."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Learning weight applied to a session's observations, by contamination class.
LEARNING_WEIGHT: dict[BaselineContamination, float] = {
    BaselineContamination.LOW: 1.0,
    BaselineContamination.MEDIUM: 0.25,
    BaselineContamination.HIGH: 0.0,
    BaselineContamination.CRITICAL: 0.0,
}


def classify_contamination(
    session: DestructiveActivitySession,
    cfg: Optional[BaselineConfig] = None,
) -> BaselineContamination:
    """Classify how much one historical session may teach the baseline.

    Evidence counters only — deliberately *not* a risk score and never
    surfaced as one. Worst-case rung wins.
    """
    cfg = cfg or BaselineConfig()

    recovery_impairing = (
        session.snapshot_deletions + session.backup_deletions
    )
    if recovery_impairing >= cfg.critical_recovery_impairing_events:
        return BaselineContamination.CRITICAL
    if (
        session.critical_resource_touched
        and recovery_impairing > 0
    ):
        return BaselineContamination.CRITICAL
    if recovery_impairing >= cfg.high_recovery_impairing_events:
        return BaselineContamination.HIGH
    if (
        session.event_count > 0
        and session.destructive_event_count >= cfg.high_destructive_events
        and session.destructive_event_count / session.event_count
        >= cfg.high_destructive_ratio
    ):
        return BaselineContamination.HIGH
    if session.protection_changes >= cfg.medium_protection_change_events:
        return BaselineContamination.MEDIUM
    if session.version_deletions >= cfg.medium_version_delete_events:
        return BaselineContamination.MEDIUM
    return BaselineContamination.LOW


# --------------------------------------------------------------------------- #
# Deterministic statistics (no ML)
# --------------------------------------------------------------------------- #


def _weighted_mean(values: Sequence[float], weights: Sequence[float]) -> Optional[float]:
    total = sum(weights)
    if total <= 0.0 or not values:
        return None
    return sum(v * w for v, w in zip(values, weights)) / total


def _weighted_spread(
    values: Sequence[float], weights: Sequence[float], mean: Optional[float]
) -> Optional[float]:
    """Weighted mean absolute deviation — robust and explainable."""
    if mean is None or not values:
        return None
    total = sum(weights)
    if total <= 0.0:
        return None
    return sum(abs(v - mean) * w for v, w in zip(values, weights)) / total


def _rate_per_hour(session: DestructiveActivitySession, count: float) -> float:
    """Events per hour with a duration floor so bursts do not divide by ~0."""
    span = max(session.duration_seconds, 60.0)
    return count * 3600.0 / span


def _event_counts(events: Sequence[ResourceActivityEvent]) -> dict[str, float]:
    """Per-session category counts from canonical event detail (accurate)."""
    counts = {
        "write": 0.0,
        "modify": 0.0,
        "rewrite": 0.0,
        "delete_family": 0.0,
        "version_delete": 0.0,
        "snapshot_delete": 0.0,
        "backup_delete": 0.0,
        "protection": 0.0,
        "total": 0.0,
        "unique_resources": 0.0,
    }
    resources: set[str] = set()
    for event in events:
        category = event.action_category
        if category is ActionCategory.CREATE:
            counts["write"] += 1
        elif category is ActionCategory.MODIFY:
            counts["modify"] += 1
        elif category is ActionCategory.REWRITE:
            counts["rewrite"] += 1
        elif category in DELETION_FAMILY_CATEGORIES:
            counts["delete_family"] += 1
            if category is ActionCategory.VERSION_DELETE:
                counts["version_delete"] += 1
            elif category is ActionCategory.SNAPSHOT_DELETE:
                counts["snapshot_delete"] += 1
            elif category in (
                ActionCategory.BACKUP_DELETE,
                ActionCategory.RECOVERY_POINT_DELETE,
            ):
                counts["backup_delete"] += 1
        elif category is ActionCategory.PROTECTION_CHANGE:
            counts["protection"] += 1
        key = event.resource_arn or event.resource_id or event.object_key
        if key:
            resources.add(key)
    counts["total"] = float(len(events))
    counts["unique_resources"] = float(len(resources))
    return counts


def _aggregate_counts(session: DestructiveActivitySession) -> dict[str, float]:
    """Per-session counts from Part 1 aggregates (documented proxies).

    Part 1 sessions do not carry plain-delete or modify counters; the
    destructive counter covers delete + version + snapshot + backup/RP
    + modify + rewrite + protection, so plain deletes are a lower bound.
    """
    destructive = float(session.destructive_event_count)
    rewrite = float(session.rewrite_count)
    protection = float(session.protection_changes)
    version = float(session.version_deletions)
    snapshot = float(session.snapshot_deletions)
    backup = float(session.backup_deletions)  # includes recovery-point deletes
    plain_lower = max(0.0, destructive - rewrite - protection - version - snapshot - backup)
    total = float(session.event_count)
    return {
        "write": total,  # documented proxy: total activity
        "modify": destructive,  # documented proxy: destructive activity
        "rewrite": rewrite,
        "delete_family": max(version + snapshot + backup, plain_lower + version + snapshot + backup),
        "version_delete": version,
        "snapshot_delete": snapshot,
        "backup_delete": backup,
        "protection": protection,
        "total": total,
        "unique_resources": float(session.unique_resource_count),
    }


@dataclass
class _WeightedStats:
    """One learned statistic: mean + spread + supporting evidence count."""

    mean: Optional[float] = None
    spread: Optional[float] = None
    evidence: int = 0

    @classmethod
    def build(cls, samples: Sequence[tuple[float, float]]) -> "_WeightedStats":
        values = [v for v, _ in samples]
        weights = [w for _, w in samples]
        mean = _weighted_mean(values, weights)
        return cls(
            mean=mean,
            spread=_weighted_spread(values, weights, mean),
            evidence=sum(1 for w in weights if w > 0.0),
        )

    def to_log_dict(self) -> dict[str, Optional[float]]:
        return {"mean": self.mean, "spread": self.spread, "evidence": self.evidence}


# --------------------------------------------------------------------------- #
# Baseline model
# --------------------------------------------------------------------------- #


@dataclass
class BehaviorBaseline:
    """Per-actor normal behavior, learned exclusively from trusted history."""

    actor_id: Optional[str]
    quality: BaselineQuality = BaselineQuality.NONE
    generation: int = 0
    baseline_version: str = "v0"
    learned_from_sessions: int = 0
    excluded_sessions: int = 0
    contamination_counts: dict[str, int] = field(default_factory=dict)

    # normal rates (events per hour)
    write_rate: _WeightedStats = field(default_factory=_WeightedStats)
    modify_rate: _WeightedStats = field(default_factory=_WeightedStats)
    delete_rate: _WeightedStats = field(default_factory=_WeightedStats)
    rewrite_rate: _WeightedStats = field(default_factory=_WeightedStats)

    # normal scope
    unique_resources_per_hour: _WeightedStats = field(default_factory=_WeightedStats)
    object_count: _WeightedStats = field(default_factory=_WeightedStats)

    # normal mix
    delete_ratio: _WeightedStats = field(default_factory=_WeightedStats)
    version_delete_ratio: _WeightedStats = field(default_factory=_WeightedStats)

    # normal sets (event detail refines these when provided)
    normal_resource_ids: frozenset[str] = frozenset()
    normal_resource_types: frozenset[str] = frozenset()
    normal_operations: frozenset[str] = frozenset()
    normal_change_windows: frozenset[str] = frozenset()

    @property
    def has_evidence(self) -> bool:
        return self.learned_from_sessions > 0 and (
            self.write_rate.mean is not None or self.modify_rate.mean is not None
        )

    def require(self) -> "BehaviorBaseline":
        """Explicit opt-in for callers that cannot proceed without a baseline.

        Raises unless the baseline carries at least LIMITED quality:
        a thin (INSUFFICIENT) or empty (NONE) baseline must never be
        silently treated as real history.
        """
        if not self.has_evidence or self.quality in (
            BaselineQuality.NONE,
            BaselineQuality.INSUFFICIENT,
        ):
            raise InsufficientHistoryError(
                "baseline has insufficient trusted history",
                context={
                    "actor_id": self.actor_id,
                    "quality": self.quality.value,
                    "learned_from_sessions": self.learned_from_sessions,
                },
            )
        return self

    def to_log_dict(self) -> dict[str, object]:
        return {
            "actor_id": self.actor_id,
            "quality": self.quality.value,
            "generation": self.generation,
            "baseline_version": self.baseline_version,
            "learned_from_sessions": self.learned_from_sessions,
            "excluded_sessions": self.excluded_sessions,
            "contamination_counts": dict(self.contamination_counts),
            "write_rate": self.write_rate.to_log_dict(),
            "modify_rate": self.modify_rate.to_log_dict(),
            "delete_rate": self.delete_rate.to_log_dict(),
            "rewrite_rate": self.rewrite_rate.to_log_dict(),
            "unique_resources_per_hour": self.unique_resources_per_hour.to_log_dict(),
            "object_count": self.object_count.to_log_dict(),
            "delete_ratio": self.delete_ratio.to_log_dict(),
            "version_delete_ratio": self.version_delete_ratio.to_log_dict(),
            "normal_resource_ids": len(self.normal_resource_ids),
            "normal_resource_types": sorted(self.normal_resource_types),
            "normal_operations": sorted(self.normal_operations),
            "normal_change_windows": sorted(self.normal_change_windows),
        }


def _change_window(timestamp) -> str:
    """Coarse 4-hour window label, e.g. ``"12-16"``."""
    hour = timestamp.hour
    return f"{(hour // 4) * 4:02d}-{(hour // 4) * 4 + 4:02d}"


def build_baseline(
    sessions: Sequence[DestructiveActivitySession],
    *,
    cfg: Optional[BaselineConfig] = None,
    actor_id: Optional[str] = None,
    generation: int = 1,
    events: Optional[Sequence[ResourceActivityEvent]] = None,
    events_by_session: Optional[dict[str, Sequence[ResourceActivityEvent]]] = None,
    approved_profiles: Optional[Sequence[ApprovedActivityProfile]] = None,
) -> Optional[BehaviorBaseline]:
    """Learn a per-actor baseline from session history (poisoning-aware).

    Event detail (``events_by_session`` or flat ``events`` grouped by
    ``event.session_id``) refines normal resource types / operations /
    change windows; events of *excluded* (HIGH/CRITICAL) sessions never
    contribute. Returns ``None`` when no session carries learning weight —
    callers then report ``BaselineQuality.NONE``.
    """
    cfg = cfg or BaselineConfig()
    actor_sessions = [s for s in sessions if actor_id is None or s.actor_id == actor_id]
    if not actor_sessions:
        return None

    grouped: dict[str, list[ResourceActivityEvent]] = {}
    if events_by_session:
        grouped = {sid: list(evts) for sid, evts in events_by_session.items()}
    else:
        for event in events or []:
            grouped.setdefault(event.session_id or "", []).append(event)
    events_by_session = grouped

    # Accurate per-category counting requires event detail; the Part 1
    # aggregates are the documented fallback (plain deletes become a lower
    # bound there — see ``_aggregate_counts``).
    use_event_counts = all(events_by_session.get(s.session_id) for s in actor_sessions)

    profiles = list(approved_profiles or [])
    eligible: list[tuple[DestructiveActivitySession, float]] = []
    excluded_event_ids: set[str] = set()
    contamination_counts: dict[str, int] = {}

    for session in actor_sessions:
        contamination = classify_contamination(session, cfg)
        contamination_counts[contamination.value] = (
            contamination_counts.get(contamination.value, 0) + 1
        )
        weight = LEARNING_WEIGHT[contamination]
        if weight <= 0.0:
            excluded_event_ids.update(session.event_ids)
            continue
        if contamination is BaselineContamination.MEDIUM and profiles:
            if match_profile(session, profiles) is not None:
                weight = 1.0
        eligible.append((session, weight))

    if not eligible:
        return None

    baseline = BehaviorBaseline(
        actor_id=actor_id,
        generation=generation,
        learned_from_sessions=len(eligible),
        excluded_sessions=len(actor_sessions) - len(eligible),
        contamination_counts=contamination_counts,
    )

    def counts_for(s: DestructiveActivitySession) -> dict[str, float]:
        if use_event_counts:
            return _event_counts(events_by_session.get(s.session_id, []))
        return _aggregate_counts(s)

    def rate_stats(selector: Callable[[dict[str, float]], float]) -> _WeightedStats:
        return _WeightedStats.build(
            [
                (
                    _rate_per_hour(s, selector(counts_for(s))),
                    w,
                )
                for s, w in eligible
            ]
        )

    baseline.write_rate = rate_stats(lambda c: c["write"])
    baseline.modify_rate = rate_stats(lambda c: c["modify"])
    baseline.delete_rate = rate_stats(lambda c: c["delete_family"])
    baseline.rewrite_rate = rate_stats(lambda c: c["rewrite"])
    baseline.unique_resources_per_hour = rate_stats(lambda c: c["unique_resources"])
    baseline.object_count = _WeightedStats.build(
        [(counts_for(s)["total"], w) for s, w in eligible]
    )

    def ratio_stats(numerator: Callable[[dict[str, float]], float]) -> _WeightedStats:
        return _WeightedStats.build(
            [(numerator(counts_for(s)), w) for s, w in eligible]
        )

    # Plain-deletion family share of all activity (event counts are
    # accurate; aggregates give the documented lower-bound proxy).
    baseline.delete_ratio = ratio_stats(
        lambda c: c["delete_family"] / c["total"] if c["total"] else 0.0
    )
    baseline.version_delete_ratio = ratio_stats(
        lambda c: c["version_delete"] / c["delete_family"] if c["delete_family"] else 0.0
    )

    # Normal sets: resources come from session aggregates; types/operations/
    # windows need event detail (absent event detail they stay empty and the
    # corresponding novelty features report unavailability honestly).
    resources: set[str] = set()
    types: set[str] = set()
    operations: set[str] = set()
    windows: set[str] = set()
    for session, _weight in eligible:
        resources.update(r for r in session.resources_touched if r)
        for event in events_by_session.get(session.session_id, []):
            if event.event_id in excluded_event_ids:
                continue
            types.add(event.resource_type.value)
            operations.add(event.action_category.value)
            windows.add(_change_window(event.timestamp))
    baseline.normal_resource_ids = frozenset(resources)
    baseline.normal_resource_types = frozenset(types)
    baseline.normal_operations = frozenset(operations)
    baseline.normal_change_windows = frozenset(windows)

    total_events = sum(s.event_count for s, _ in eligible)
    if len(eligible) >= cfg.min_sessions_for_good:
        baseline.quality = BaselineQuality.GOOD
    elif len(eligible) >= cfg.min_sessions_for_limited:
        baseline.quality = BaselineQuality.LIMITED
    else:
        baseline.quality = BaselineQuality.INSUFFICIENT

    digest = hashlib.sha256(
        "|".join(
            [
                str(actor_id),
                str(len(eligible)),
                str(total_events),
                str(generation),
                baseline.quality.value,
            ]
        ).encode()
    ).hexdigest()[:12]
    baseline.baseline_version = f"gen{generation}-{digest}"
    return baseline


# --------------------------------------------------------------------------- #
# Actor / resource novelty
# --------------------------------------------------------------------------- #


@dataclass
class ActorNovelty:
    """How novel a session's targets, operations and scope are for the actor."""

    resource_novelty: Optional[MeasuredValue] = None
    operation_novelty: Optional[MeasuredValue] = None
    scope_novelty: Optional[MeasuredValue] = None


def measure_novelty(
    baseline: Optional[BehaviorBaseline],
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent] = (),
) -> ActorNovelty:
    """Measure actor novelty of one session against its baseline.

    All three values are fractions in ``[0, 1]`` (0 = everything familiar).
    Unavailable — with a reason — when there is no usable baseline or the
    required detail was not provided.
    """
    if baseline is None or not baseline.has_evidence:
        reason = "no_baseline" if baseline is None else "baseline_without_evidence"
        return ActorNovelty(
            resource_novelty=MeasuredValue.unavailable(reason, contributors=("baseline",)),
            operation_novelty=MeasuredValue.unavailable(reason, contributors=("baseline",)),
            scope_novelty=MeasuredValue.unavailable(reason, contributors=("baseline",)),
        )

    resources = {r for r in session.resources_touched if r}
    novel_resources = resources - baseline.normal_resource_ids
    resource_fraction = len(novel_resources) / len(resources) if resources else None

    resource_novelty = (
        MeasuredValue.measured(
            resource_fraction,
            method="novel_resource_fraction",
            contributors=("baseline",),
            raw={
                "session_resources": len(resources),
                "novel_resources": len(novel_resources),
                "baseline_resources": len(baseline.normal_resource_ids),
            },
        )
        if resource_fraction is not None
        else MeasuredValue.unavailable("no_resource_targets", contributors=("baseline",))
    )

    session_events = list(events) if events else []
    if session_events:
        operations = {e.action_category.value for e in session_events}
        novel_operations = operations - baseline.normal_operations
        operation_novelty = MeasuredValue.measured(
            len(novel_operations) / len(operations) if operations else 0.0,
            method="novel_operation_fraction",
            contributors=("baseline",),
            raw={
                "session_operations": len(operations),
                "novel_operations": len(novel_operations),
            },
        )
        types = {e.resource_type.value for e in session_events}
        novel_types = types - baseline.normal_resource_types
        scope_novelty = (
            MeasuredValue.measured(
                len(novel_types) / len(types),
                method="novel_resource_type_fraction",
                contributors=("baseline",),
                raw={"session_types": len(types), "novel_types": len(novel_types)},
            )
            if baseline.normal_resource_types
            else MeasuredValue.unavailable(
                "baseline_lacks_resource_types", contributors=("baseline",)
            )
        )
    else:
        operation_novelty = MeasuredValue.unavailable(
            "event_detail_missing", contributors=("baseline",)
        )
        scope_novelty = MeasuredValue.unavailable(
            "event_detail_missing", contributors=("baseline",)
        )

    return ActorNovelty(
        resource_novelty=resource_novelty,
        operation_novelty=operation_novelty,
        scope_novelty=scope_novelty,
    )


# --------------------------------------------------------------------------- #
# Versioned baseline store
# --------------------------------------------------------------------------- #


class BaselineStore:
    """Versioned holder of per-actor baselines (prior generations retained)."""

    def __init__(
        self,
        approved_profiles: Optional[Sequence[ApprovedActivityProfile]] = None,
    ) -> None:
        self._current: dict[Optional[str], BehaviorBaseline] = {}
        self._history: dict[Optional[str], list[BehaviorBaseline]] = {}
        self._approved_profiles = list(approved_profiles or [])
        self._generation = 0

    @property
    def generation(self) -> int:
        return self._generation

    def build(
        self,
        sessions: Sequence[DestructiveActivitySession],
        *,
        cfg: Optional[BaselineConfig] = None,
        actor_id: Optional[str] = None,
        events: Optional[Sequence[ResourceActivityEvent]] = None,
        events_by_session: Optional[dict[str, Sequence[ResourceActivityEvent]]] = None,
    ) -> Optional[BehaviorBaseline]:
        """Learn (or re-learn) a baseline and store it as the current version."""
        self._generation += 1
        baseline = build_baseline(
            sessions,
            cfg=cfg,
            actor_id=actor_id,
            generation=self._generation,
            events=events,
            events_by_session=events_by_session,
            approved_profiles=self._approved_profiles,
        )
        if baseline is None:
            return None
        if baseline.actor_id in self._current:
            self._history.setdefault(baseline.actor_id, []).append(self._current[baseline.actor_id])
        self._current[baseline.actor_id] = baseline
        return baseline

    def get(self, actor_id: Optional[str]) -> Optional[BehaviorBaseline]:
        return self._current.get(actor_id)

    def history(self, actor_id: Optional[str]) -> list[BehaviorBaseline]:
        return list(self._history.get(actor_id, []))

    def get_or_build(
        self,
        actor_id: Optional[str],
        sessions: Sequence[DestructiveActivitySession],
        *,
        cfg: Optional[BaselineConfig] = None,
        events: Optional[Sequence[ResourceActivityEvent]] = None,
        events_by_session: Optional[dict[str, Sequence[ResourceActivityEvent]]] = None,
    ) -> Optional[BehaviorBaseline]:
        """Return the stored baseline for ``actor_id`` or learn a fresh one.

        A freshly learned baseline is *not* persisted (callers such as
        ``extract_features`` use leave-one-out history that must not
        contaminate the operational store).
        """
        existing = self._current.get(actor_id)
        if existing is not None:
            return existing
        return build_baseline(
            sessions,
            cfg=cfg,
            actor_id=actor_id,
            generation=self._generation + 1,
            events=events,
            events_by_session=events_by_session,
            approved_profiles=self._approved_profiles,
        )

    def novelty(
        self,
        session: DestructiveActivitySession,
        events: Sequence[ResourceActivityEvent] = (),
    ) -> ActorNovelty:
        return measure_novelty(self._current.get(session.actor_id), session, events)
