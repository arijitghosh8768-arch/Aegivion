"""Risk fusion / scoring interface.

Part 1 defines the contract. No implementation: producing an exfiltration
risk score without the full analysis stack would be fabrication.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.base import AnalysisResult
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession


class RiskBreakdown(BaseModel):
    """Component contributions to a fused risk score (schema only)."""

    components: dict[str, float] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class RiskScore(BaseModel):
    """Fused risk output for one session (schema only in Part 1)."""

    session_id: str
    risk_score: float | None = None
    breakdown: RiskBreakdown = Field(default_factory=RiskBreakdown)
    analyst_notes: list[str] = Field(default_factory=list)


class RiskScorer(ABC):
    """Contract for Part 2 risk fusion."""

    @abstractmethod
    def score(self, session: DataAccessSession, analyses: list[AnalysisResult]) -> RiskScore:
        """Fuse analysis evidence into a risk score."""


class NotImplementedRiskScorer(RiskScorer):
    """Part 1 stub: raises loudly rather than emitting a fake score."""

    def score(self, session: DataAccessSession, analyses: list[AnalysisResult]) -> RiskScore:
        raise NotImplementedError(
            "risk fusion ships in a later part; Part 1 records analysis evidence only"
        )
