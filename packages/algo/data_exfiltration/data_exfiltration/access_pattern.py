"""Access-pattern analysis: how the data was touched.

Signals cover actor familiarity (against supplied expected consumers),
enumeration/list intensity, error counts, and access-hour context.
Risk judgments about these signals belong to Part 2.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from algo.data_exfiltration.data_exfiltration.base import AnalysisModule, AnalysisResult
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession


class AccessPatternAnalyzer(AnalysisModule):
    name = "access_pattern"

    def __init__(self, expected_consumers: set[str] | None = None) -> None:
        self._expected = expected_consumers

    def analyze(self, session: DataAccessSession, context: dict[str, Any] | None = None) -> AnalysisResult:
        signals: dict[str, Any] = {"session_id": session.session_id}

        expected = self._expected
        if context and isinstance(context.get("expected_consumers"), (set, list)):
            expected = set(context["expected_consumers"])

        actor = session.actor_id
        if expected is None:
            signals["actor_familiarity"] = "not supplied"
        else:
            signals["actor_familiarity"] = "expected" if actor in expected else "unexpected"
            signals["expected_consumers"] = sorted(expected)

        total = session.event_count or 0
        signals["event_count"] = total
        signals["enumerate_list_count"] = session.enumerate_list_count
        signals["enumerate_list_ratio"] = (
            session.enumerate_list_count / total if total > 0 else None
        )
        signals["error_event_count"] = session.error_event_count

        if session.start_time_epoch_ms is not None:
            hour = datetime.fromtimestamp(session.start_time_epoch_ms / 1000.0, tz=timezone.utc).hour
            signals["start_hour_utc"] = hour

        if session.event_count:
            signals["request_rate_per_minute"] = (
                session.request_count / max(0.001, (session.end_time_epoch_ms - session.start_time_epoch_ms) / 60000.0)
                if session.start_time_epoch_ms is not None
                and session.end_time_epoch_ms is not None
                and session.end_time_epoch_ms > session.start_time_epoch_ms
                else None
            )

        return AnalysisResult(analysis_name=self.name, signals=signals)
