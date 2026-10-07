"""Temporal feature engine — **Part 3**.

For each mandated window (1 minute / 5 minutes / 15 minutes / 1 hour /
6 hours / 24 hours) computes the mandated metrics over sliding windows of
a session's events:

- ``event_count``, ``delete_count``, ``modify_count``,
  ``version_delete_count``, ``snapshot_delete_count``,
  ``backup_delete_count``
- ``unique_resources``, ``unique_object_scopes``
- ``action_diversity``

All values are the maximum over all sliding windows of that size (two-
pointer sweep with prefix sums for the counting metrics, direct census
for the set metrics). Metrics for a session shorter than a window equal
the whole-session census — recorded honestly, not extrapolated.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional, Sequence

from detection.cloud_destruction.registry import TEMPORAL_MODEL_VERSION
from detection.cloud_destruction.schemas import (
    ActionCategory,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

#: Mandated window sizes in seconds.
WINDOW_SECONDS: tuple[int, ...] = (60, 300, 900, 3600, 21600, 86400)

#: Metrics reported per window.
METRIC_NAMES: tuple[str, ...] = (
    "event_count",
    "delete_count",
    "modify_count",
    "version_delete_count",
    "snapshot_delete_count",
    "backup_delete_count",
    "unique_resources",
    "unique_object_scopes",
    "action_diversity",
)

_COUNT_METRICS = ("delete_count", "modify_count", "version_delete_count", "snapshot_delete_count", "backup_delete_count")

__all__ = ["WINDOW_SECONDS", "METRIC_NAMES", "TemporalWindowFeatures", "build_temporal_features"]


@dataclass
class TemporalWindowFeatures:
    """Temporal window features for one session (versioned contract)."""

    session_id: str
    windows: dict[str, dict[str, float]]
    """``"60s"`` → {metric → max-over-sliding-windows}."""
    peak_window: str
    """Window key whose ``event_count`` peak is highest."""
    model_version: str = TEMPORAL_MODEL_VERSION

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "model_version": self.model_version,
            "peak_window": self.peak_window,
            "windows": self.windows,
        }

    def metric(self, window_key: str, metric: str) -> Optional[float]:
        return self.windows.get(window_key, {}).get(metric)


def _scope_of(resource: Optional[str]) -> Optional[str]:
    """``bucket/prefix/object`` → ``bucket/prefix``; plain ids pass through."""
    if resource and "/" in resource:
        return resource.rsplit("/", 1)[0]
    return resource


def build_temporal_features(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> TemporalWindowFeatures:
    """Build the mandated window features for one session.

    ``unique_object_scopes`` counts distinct ``bucket/prefix`` scopes for
    S3-style keys (terminal ``/`` segment dropped) and distinct resource
    ids otherwise.
    """
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    if not ordered:
        empty = {name: 0.0 for name in METRIC_NAMES}
        return TemporalWindowFeatures(
            session_id=session.session_id,
            windows={f"{w}s": dict(empty) for w in WINDOW_SECONDS},
            peak_window=f"{max(WINDOW_SECONDS)}s",
        )

    times: list[datetime] = [e.timestamp for e in ordered]
    # prefix sums for the counting metrics:
    # [delete, modify, version_delete, snapshot_delete, backup/RP-delete]
    prefix: list[tuple[int, int, int, int, int]] = [(0, 0, 0, 0, 0)]
    resources: list[Optional[str]] = []
    scopes: list[Optional[str]] = []
    categories: list[str] = []
    for event in ordered:
        category = event.action_category
        d, m, v, s, b = prefix[-1]
        if category is ActionCategory.DELETE:
            d += 1
        elif category is ActionCategory.MODIFY:
            m += 1
        elif category is ActionCategory.VERSION_DELETE:
            v += 1
        elif category is ActionCategory.SNAPSHOT_DELETE:
            s += 1
        elif category in (ActionCategory.BACKUP_DELETE, ActionCategory.RECOVERY_POINT_DELETE):
            b += 1
        prefix.append((d, m, v, s, b))
        resource = event.resource_arn or event.resource_id or event.object_key
        resources.append(resource)
        scopes.append(_scope_of(resource))
        categories.append(category.value)

    def census(left: int, right: int) -> tuple[int, int, int]:
        """Distinct resources/scopes/categories in the inclusive window."""
        res = {r for r in resources[left : right + 1] if r}
        scp = {s for s in scopes[left : right + 1] if s}
        cat = set(categories[left : right + 1])
        return len(res), len(scp), len(cat)

    windows: dict[str, dict[str, float]] = {}
    peak_window = f"{WINDOW_SECONDS[0]}s"
    peak_count = -1.0
    for window in WINDOW_SECONDS:
        delta = timedelta(seconds=window)
        best: dict[str, float] = {name: 0.0 for name in METRIC_NAMES}
        left = 0
        for right in range(len(ordered)):
            while times[right] - times[left] > delta:
                left += 1
            best["event_count"] = max(best["event_count"], float(right - left + 1))
            hi = prefix[right + 1]
            lo = prefix[left]
            for index, metric in enumerate(_COUNT_METRICS):
                best[metric] = max(best[metric], float(hi[index] - lo[index]))
            res_n, scope_n, cat_n = census(left, right)
            best["unique_resources"] = max(best["unique_resources"], float(res_n))
            best["unique_object_scopes"] = max(best["unique_object_scopes"], float(scope_n))
            best["action_diversity"] = max(best["action_diversity"], float(cat_n))
        key = f"{window}s"
        windows[key] = best
        if best["event_count"] > peak_count:
            peak_count = best["event_count"]
            peak_window = key

    return TemporalWindowFeatures(
        session_id=session.session_id,
        windows=windows,
        peak_window=peak_window,
    )
