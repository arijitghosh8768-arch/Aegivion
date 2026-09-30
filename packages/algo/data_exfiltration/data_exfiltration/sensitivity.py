"""Sensitivity analysis: surface what external enrichment told us.

This engine never classifies content. Signals here describe which
sessions touched data that Macie (or another enrichment source) marked as
sensitive, and how complete that enrichment is.
"""

from __future__ import annotations

from typing import Any

from algo.data_exfiltration.data_exfiltration.base import AnalysisModule, AnalysisResult
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, SensitivityLevel


class SensitivityAnalyzer(AnalysisModule):
    name = "sensitivity"

    def analyze(self, session: DataAccessSession, context: dict[str, Any] | None = None) -> AnalysisResult:
        signals: dict[str, Any] = {"session_id": session.session_id}

        summary = session.sensitivity_summary
        if summary is None or summary.measurement is None:
            signals["sensitivity_presence"] = "unavailable"
            signals["sensitivity_unavailable_reason"] = (
                summary.unavailable_reason if summary else "no enrichment was applied"
            )
            return AnalysisResult(analysis_name=self.name, signals=signals)

        measurement = summary.measurement
        signals["sensitivity_presence"] = measurement.presence.value
        signals["max_sensitivity_score"] = measurement.value
        signals["sensitivity_provenance"] = measurement.provenance()

        # sensitivity_level is event-level enrichment; the session keeps the
        # most severe level contributed by any event (see session aggregate)
        signals["levels_contributed"] = sorted(
            {m.detail or "" for m in measurement.measurements if m.detail}
        )

        return AnalysisResult(analysis_name=self.name, signals=signals)
