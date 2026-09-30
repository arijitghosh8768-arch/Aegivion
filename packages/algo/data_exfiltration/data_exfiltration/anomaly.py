"""ML anomaly detection interface.

Part 1 defines the contract only. The shipped implementation raises
NotImplementedError — there is deliberately no heuristic masquerading as
ML, and no placeholder score.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.schemas import (
    DataAccessSession,
    DataBaselineVersion,
    DataBehavioralFeatures,
)


class AnomalyResult(BaseModel):
    """Outcome of anomaly evaluation for one session (schema only)."""

    session_id: str
    anomaly_score: float | None = None
    model_id: str | None = None
    model_version: str | None = None
    explanations: dict[str, Any] = Field(default_factory=dict)


class AnomalyDetector(ABC):
    """Contract for Part 2 anomaly models."""

    model_id: str = "abstract"

    @abstractmethod
    def fit(self, features: list[DataBehavioralFeatures]) -> None:
        """Train on historical session features."""

    @abstractmethod
    def score(
        self,
        features: DataBehavioralFeatures,
        baseline: DataBaselineVersion | None = None,
        session: DataAccessSession | None = None,
    ) -> AnomalyResult:
        """Score one session's features against the baseline."""


class NotImplementedAnomalyDetector(AnomalyDetector):
    """Part 1 stub: anomaly detection is intentionally not implemented.

    Any pipeline that asks for anomaly scores gets a loud failure instead
    of silent zeros.
    """

    model_id = "not-implemented"

    def fit(self, features: list[DataBehavioralFeatures]) -> None:
        raise NotImplementedError(
            "ML anomaly detection ships in a later part; Part 1 provides the interface only"
        )

    def score(
        self,
        features: DataBehavioralFeatures,
        baseline: DataBaselineVersion | None = None,
        session: DataAccessSession | None = None,
    ) -> AnomalyResult:
        raise NotImplementedError(
            "ML anomaly detection ships in a later part; Part 1 provides the interface only"
        )
