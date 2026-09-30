"""Multi-scope behavioral baseline engine.

Scopes: actor / resource / workload / destination. Lookbacks: 7/30/90
days. History is stored as raw observations (entity, metric, value, time,
influence) and statistics are computed on demand with robust estimators
(median, percentiles, MAD).

Cold start: an entity with <= ``cold_start_max_observations`` trusted
observations has no personal statistics; callers fall back to a peer
group. Absence of history is never a deviation: ``stats_for`` returns
None and ``deviation`` treats "no history anywhere" as 0.0.

Poisoning protection: observations carry a ``BaselineInfluence``; only
ELIGIBLE observations shape trusted statistics. LIMITED/BLOCKED records
are kept for audit but excluded from the trusted pool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from algo.data_exfiltration.data_exfiltration.config import BaselineEngineConfig
from algo.data_exfiltration.data_exfiltration.stats import deviation_score, mad, median, percentile

from .baseline_guard import BaselineInfluence

Scope = Literal["actor", "resource", "workload", "destination"]
Metric = Literal[
    "bytes", "objects", "requests", "resources", "hour",
    "destinations", "resources_per_session", "sensitivity", "duration_s",
]

_TRUSTED = BaselineInfluence.ELIGIBLE


@dataclass
class Observation:
    """One behavioral observation with its baseline influence."""

    entity: str
    metric: str
    value: float
    observed_at_epoch_ms: float
    influence: BaselineInfluence = BaselineInfluence.ELIGIBLE
    risk: str = "low"
    peer_group: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "metric": self.metric,
            "value": self.value,
            "observed_at_epoch_ms": self.observed_at_epoch_ms,
            "influence": self.influence.value,
            "risk": self.risk,
            "peer_group": self.peer_group,
        }


@dataclass
class BaselineSnapshot:
    """What the baseline said about one entity/metric at decision time."""

    scope: Scope
    entity: str
    metric: str
    lookback_seconds: float
    values: list[float] = field(default_factory=list)
    median: float | None = None
    p95: float | None = None
    mad: float | None = None
    source: str = "personal"
    """``personal`` | ``peer`` | ``cold_start``."""
    peer_group: str | None = None
    baseline_quality: float = 0.0
    cold_start: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "entity": self.entity,
            "metric": self.metric,
            "lookback_seconds": self.lookback_seconds,
            "count": len(self.values),
            "median": self.median,
            "p95": self.p95,
            "mad": self.mad,
            "source": self.source,
            "peer_group": self.peer_group,
            "baseline_quality": self.baseline_quality,
            "cold_start": self.cold_start,
        }


class BaselineEngine:
    """In-memory observation store + robust statistics (Part 2).

    A later part can swap the store for the database without changing
    the interface: ``record`` / ``stats_for`` / ``peer_stats`` /
    ``deviation`` / ``versioned_snapshot``.
    """

    def __init__(self, config: BaselineEngineConfig | None = None) -> None:
        self._config = config or BaselineEngineConfig()
        # (scope, metric) -> {entity: [Observation, ...]}
        self._obs: dict[tuple[str, str], dict[str, list[Observation]]] = {}

    # ------------------------------------------------------------------
    # recording
    # ------------------------------------------------------------------

    def record(
        self,
        scope: Scope,
        metric: Metric,
        entity: str,
        value: float,
        observed_at_epoch_ms: float,
        *,
        influence: BaselineInfluence = BaselineInfluence.ELIGIBLE,
        risk: str = "low",
        peer_group: str | None = None,
    ) -> Observation:
        """Record one observation into scope/metric/entity history."""
        obs = Observation(
            entity=entity,
            metric=metric,
            value=value,
            observed_at_epoch_ms=observed_at_epoch_ms,
            influence=influence,
            risk=risk,
            peer_group=peer_group,
        )
        key = (scope, metric)
        self._obs.setdefault(key, {}).setdefault(entity, []).append(obs)
        return obs

    # ------------------------------------------------------------------
    # statistics
    # ------------------------------------------------------------------

    def stats_for(
        self,
        scope: Scope,
        metric: str,
        entity: str,
        *,
        lookback_seconds: float | None = None,
        end_epoch_ms: float | None = None,
    ) -> BaselineSnapshot | None:
        """Robust stats for entity/metric within the lookback window.

        Returns None when the entity has no observations at all (the
        caller decides the cold-start fallback); when observations exist
        but none are trusted, the snapshot reports ``cold_start=True``
        with empty statistics.
        """
        entities = self._obs.get((scope, metric))
        if not entities:
            return None
        obs_list = entities.get(entity, [])
        if not obs_list:
            return None

        end = end_epoch_ms if end_epoch_ms is not None else _now_ms()
        lookback = lookback_seconds or self._config.default_lookback
        start = end - lookback * 1000.0

        # half-open window (start, end]: an observation exactly N days back
        # belongs to the N-day baseline, not the (N+1)-day one
        in_window = [o for o in obs_list if start < o.observed_at_epoch_ms <= end]
        if not in_window:
            return None

        trusted = [o for o in in_window if o.influence is _TRUSTED]
        snap = BaselineSnapshot(
            scope=scope,
            entity=entity,
            metric=metric,
            lookback_seconds=lookback,
            source="personal",
            baseline_quality=min(1.0, len(trusted) / max(1, self._config.min_observations)),
        )
        if not trusted:
            snap.cold_start = True
            snap.baseline_quality = 0.0
            return snap
        snap.cold_start = len(trusted) <= self._config.cold_start_max_observations
        values = [o.value for o in trusted]
        snap.values = values
        snap.median = median(values)
        snap.p95 = percentile(values, 95)
        snap.mad = mad(values)
        return snap

    def peer_stats(
        self,
        scope: Scope,
        metric: str,
        peer_group: str,
        *,
        lookback_seconds: float | None = None,
        end_epoch_ms: float | None = None,
        exclude_entity: str | None = None,
    ) -> BaselineSnapshot | None:
        """Statistics over a peer group (cold-start fallback).

        Combines trusted observations of all group members, optionally
        excluding the entity being judged (avoid self-contamination).
        """
        entities = self._obs.get((scope, metric))
        if not entities:
            return None
        end = end_epoch_ms if end_epoch_ms is not None else _now_ms()
        lookback = lookback_seconds or self._config.default_lookback
        start = end - lookback * 1000.0
        values: list[float] = []
        for entity, obs_list in entities.items():
            if exclude_entity and entity == exclude_entity:
                continue
            if not any(o.peer_group == peer_group for o in obs_list):
                continue
            values.extend(
                o.value for o in obs_list
                if o.influence is _TRUSTED and start < o.observed_at_epoch_ms <= end
            )
        if not values:
            return None
        snap = BaselineSnapshot(
            scope=scope,
            entity=peer_group,
            metric=metric,
            lookback_seconds=lookback,
            values=values,
            source="peer",
            peer_group=peer_group,
            baseline_quality=min(
                1.0,
                len(values)
                / max(1, self._config.min_observations * max(1, self._config.min_peer_group_size)),
            ),
        )
        snap.median = median(values)
        snap.p95 = percentile(values, 95)
        snap.mad = mad(values)
        return snap

    # ------------------------------------------------------------------
    # deviation evaluation
    # personal -> peer -> none (absence of history is not a deviation)
    # ------------------------------------------------------------------

    def deviation(
        self,
        scope: Scope,
        metric: str,
        entity: str,
        observed: float,
        *,
        end_epoch_ms: float | None = None,
        peer_group: str | None = None,
    ) -> tuple[float, BaselineSnapshot | None]:
        """Robust deviation of *observed* against personal, then peer history.

        Returns (0.0, None) when neither exists — absence of history is
        never classified as suspicious.
        """
        end = end_epoch_ms if end_epoch_ms is not None else _now_ms()
        snap = self.stats_for(scope, metric, entity, end_epoch_ms=end)
        if snap is not None and snap.values and not snap.cold_start:
            return (
                deviation_score(observed, snap.values, gate=self._config.mad_z_gate),
                snap,
            )
        if peer_group is not None:
            psnap = self.peer_stats(
                scope, metric, peer_group, end_epoch_ms=end, exclude_entity=entity
            )
            if psnap is not None:
                return (
                    deviation_score(observed, psnap.values, gate=self._config.mad_z_gate),
                    psnap,
                )
        return 0.0, None

    # ------------------------------------------------------------------
    # versioned snapshots
    # ------------------------------------------------------------------

    def versioned_snapshot(self, note: str = "") -> dict[str, Any]:
        """Exportable, versioned snapshot of the current baseline state."""
        import hashlib
        import json

        payload: dict[str, Any] = {
            "created_at_epoch_ms": _now_ms(),
            "note": note,
            "observations": [
                o.as_dict()
                for observations in self._obs.values()
                for obs_list in observations.values()
                for o in obs_list
            ],
        }
        blob = json.dumps(payload, sort_keys=True).encode()
        payload["version_id"] = "bl-" + hashlib.sha256(blob).hexdigest()[:12]
        return payload


def _now_ms() -> float:
    return datetime.now(timezone.utc).timestamp() * 1000.0
