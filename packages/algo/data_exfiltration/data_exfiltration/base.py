"""Shared result contracts for analysis and scoring stages.

Part 1 ships a no-op passthrough analyzer: the pipeline runs end to end
and every analysis result carries the evidence that *was* computed. Risk
values are structurally present (schema) but never populated here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession


class AnalysisResult(BaseModel):
    """Output of one analysis stage over one session.

    ``signals`` carries structured evidence (counts, observations).
    ``risk_score`` is set by the scorer stage only — analysis stages must
    leave it as None in Part 1.
    """

    analysis_name: str
    signals: dict[str, Any] = Field(default_factory=dict)
    risk_score: float | None = None


class AnalysisModule(ABC):
    """A named stage over normalized sessions."""

    name: str = "analysis"

    @abstractmethod
    def analyze(self, session: DataAccessSession, context: dict[str, Any] | None = None) -> AnalysisResult:
        """Return evidence for *session*. Must not mutate the session."""

    def run(self, session: DataAccessSession, context: dict[str, Any] | None = None) -> AnalysisResult:
        """Hook template: run analysis, stamp the module name, return result."""
        result = self.analyze(session, context)
        result.analysis_name = self.name
        return result


class PassthroughAnalyzer(AnalysisModule):
    """Produces an empty evidence set without computing anything."""

    name = "passthrough"

    def analyze(self, session: DataAccessSession, context: dict[str, Any] | None = None) -> AnalysisResult:
        return AnalysisResult(analysis_name=self.name, signals={"session_id": session.session_id})
