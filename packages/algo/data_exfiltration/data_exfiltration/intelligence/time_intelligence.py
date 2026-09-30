"""Time intelligence: access-hour behavior against history and schedules.

The hour-of-day is circular (23:00 is next to 00:00), so deviation uses
circular hour distance, never linear z-scores over the clock. Approved
schedules (e.g. the daily 02:00 backup) suppress anomalies for accesses
inside their window: a scheduled 02:00 backup is expected; an
unscheduled single 02:00 access by an office worker is anomalous.

Cold start: no history -> score unavailable, never suspicious.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.baseline import _percentile  # reuse interp; noqa
from algo.data_exfiltration.data_exfiltration.intelligence.baseline_engine import BaselineEngine
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession


@dataclass
class ApprovedSchedule:
    """A recurring, approved access window."""

    name: str
    start_hour_utc: int
    end_hour_utc: int
    """Inclusive start, exclusive end; may wrap midnight (e.g. 23 -> 3)."""
    days_of_week: frozenset[int] | None = None
    """0=Monday .. 6=Sunday; None = every day."""

    def covers(self, when: datetime) -> bool:
        hour = when.hour
        if self.start_hour_utc <= self.end_hour_utc:
            in_hours = self.start_hour_utc <= hour < self.end_hour_utc
        else:
            in_hours = hour >= self.start_hour_utc or hour < self.end_hour_utc
        if not in_hours:
            return False
        if self.days_of_week is not None and when.weekday() not in self.days_of_week:
            return False
        return True


class TimeAssessment(BaseModel):
    session_id: str
    time_score: float | None = None
    availability: str = "unavailable"
    status: str = "no_history"
    """``approved_schedule`` | ``history`` | ``no_history``."""
    start_hour_utc: int | None = None
    weekday: int | None = None
    matched_schedule: str | None = None
    min_hour_distance: float | None = None
    weekday_novel: bool | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


def hour_distance(a: int, b: int) -> float:
    """Circular distance on the 24h clock."""
    d = abs(a - b) % 24
    return float(min(d, 24 - d))


def record_time_history(engine: BaselineEngine, session: DataAccessSession) -> None:
    """Record start hour/weekday of a session into the actor baseline."""
    if session.start_time_epoch_ms is None or not session.actor_id:
        return
    when = datetime.fromtimestamp(session.start_time_epoch_ms / 1000.0, tz=timezone.utc)
    engine.record("actor", "hour", session.actor_id, float(when.hour), session.start_time_epoch_ms)
    engine.record("actor", "weekday", session.actor_id, float(when.weekday()), session.start_time_epoch_ms)


def time_anomaly(
    session: DataAccessSession,
    engine: BaselineEngine | None = None,
    schedules: Sequence[ApprovedSchedule] = (),
    *,
    at_epoch_ms: float | None = None,
) -> TimeAssessment:
    """Evaluate session start time against schedules, then history."""
    when = datetime.fromtimestamp(
        (at_epoch_ms or session.start_time_epoch_ms or 0.0) / 1000.0, tz=timezone.utc
    ) if (at_epoch_ms is not None or session.start_time_epoch_ms is not None) else None

    assessment = TimeAssessment(session_id=session.session_id)
    if when is None:
        return assessment
    assessment.start_hour_utc = when.hour
    assessment.weekday = when.weekday()

    for schedule in schedules:
        if schedule.covers(when):
            assessment.status = "approved_schedule"
            assessment.matched_schedule = schedule.name
            assessment.time_score = 0.0
            assessment.availability = "observed"
            return assessment

    snap = engine.stats_for("actor", "hour", session.actor_id or "", end_epoch_ms=when.timestamp() * 1000.0) if engine else None
    if snap is None or not snap.values or snap.cold_start:
        assessment.status = "no_history"
        assessment.availability = "cold_start"
        assessment.detail["reason"] = "insufficient trusted hour history for this actor"
        return assessment

    hours = [int(round(v)) for v in snap.values]
    min_distance = min(hour_distance(when.hour, h) for h in hours)
    assessment.min_hour_distance = min_distance

    # hour component: within 1h of any usual hour -> 0; ramps to 1.0 at 6h
    hour_component = 0.0 if min_distance <= 1.0 else min(1.0, (min_distance - 1.0) / 6.0)

    # weekday component: small penalty when the weekday was never accessed
    weekday_values = {
        int(round(v))
        for v in _safe_weekday_values(engine, session.actor_id or "", when)
    }
    weekday_novel = bool(weekday_values) and when.weekday() not in weekday_values
    assessment.weekday_novel = weekday_novel if weekday_values else None

    score = hour_component + (0.2 if weekday_novel else 0.0)
    assessment.time_score = round(min(1.0, score), 4)
    assessment.availability = "observed"
    assessment.status = "history"
    assessment.detail = {
        "history_hours": sorted(set(hours)),
        "history_sessions": len(snap.values),
        "baseline_quality": snap.baseline_quality,
    }
    return assessment


def _safe_weekday_values(engine: BaselineEngine | None, actor_id: str, when: datetime) -> list[float]:
    if engine is None:
        return []
    snap = engine.stats_for("actor", "weekday", actor_id, end_epoch_ms=when.timestamp() * 1000.0)
    return snap.values if snap is not None else []
