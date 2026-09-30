"""Scoring stack: behavioral features -> risk + confidence + severity.

One object per model variant (A/B/C/D). Produces a ``ScoredSession``
carrying the full model identity (model_name/version, feature_version,
baseline_version, scoring_version, variant) so every downstream finding
is reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.feature_vector import FEATURE_VERSION
from algo.data_exfiltration.data_exfiltration.ml.fusion import FusionResult, WeightedFusionEngine
from algo.data_exfiltration.data_exfiltration.ml.rules import RulePolicy
from algo.data_exfiltration.data_exfiltration.ml.severity import Severity, severity_from, SeverityInputs
from algo.data_exfiltration.data_exfiltration.ml.confidence_engine import (
    ConfidenceAssessment,
    ConfidenceEngine,
    FindingConfidenceCalibrator,
)
from algo.data_exfiltration.data_exfiltration.ml.versioning import MODEL_NAME, MODEL_VERSION, SCORING_VERSION, ModelVersionInfo

VARIANT_COMPONENTS = {
    "A": ["rules"],
    "B": ["rules", "baseline_fusion"],
    "C": ["rules", "baseline_fusion", "isolation_forest"],
    "D": ["rules", "baseline_fusion", "isolation_forest", "supervised"],
}


class ScoredSession(BaseModel):
    """Everything the scoring stack concluded about one session."""

    session_id: str
    variant: str
    risk_score: float
    rules_score: float | None = None
    anomaly_score: float | None = None
    supervised_score: float | None = None
    confidence_score: float | None = None
    confidence_state: str = "insufficient_data"
    severity: str = "low"
    contributions: dict[str, float] = Field(default_factory=dict)
    missing_components: list[str] = Field(default_factory=list)
    fired_rules: list[str] = Field(default_factory=list)
    model: ModelVersionInfo

    def as_metadata(self) -> dict[str, Any]:
        return self.model.model_dump()


@dataclass
class ScoringStack:
    """A configured scoring variant over behavioral features."""

    variant: str = "B"
    rule_policy: RulePolicy = field(default_factory=RulePolicy)
    fusion: WeightedFusionEngine = field(default_factory=WeightedFusionEngine)
    anomaly_model: Any = None
    """Fitted IsolationForest (variants C/D)."""
    supervised_model: Any = None
    """Trained supervised model (variant D, gated)."""
    calibrator: FindingConfidenceCalibrator | None = None
    confidence_engine: ConfidenceEngine = field(default_factory=ConfidenceEngine)
    baseline_version: str | None = None
    supervised_weight: float = 0.5
    """Blend weight of supervised vs IF anomaly signal in variant D."""

    def __post_init__(self) -> None:
        if self.confidence_engine._calibrator is None and self.calibrator is not None:
            self.confidence_engine = ConfidenceEngine(self.calibrator)

    @property
    def version(self) -> ModelVersionInfo:
        return ModelVersionInfo(
            model_name=MODEL_NAME,
            model_version=MODEL_VERSION,
            feature_version=FEATURE_VERSION,
            baseline_version=self.baseline_version,
            scoring_version=SCORING_VERSION,
            variant=self.variant,
            extra={
                "components": VARIANT_COMPONENTS.get(self.variant, []),
                "anomaly_model": getattr(self.anomaly_model, "version", lambda: None)(),
                "weights_version": self.fusion.weights_version,
            },
        )

    # ------------------------------------------------------------------

    def score(self, fset: BehavioralFeatureSet) -> ScoredSession:
        rules = self.rule_policy.evaluate(fset)

        anomaly_score: float | None = None
        supervised_score: float | None = None
        if self.anomaly_model is not None and fset.session_features.get("feature_vector") is not None:
            vector = fset.session_features["feature_vector"]
            anomaly_score = float(self.anomaly_model.score(vector))

        effective_anomaly = anomaly_score
        if self.variant == "D" and self.supervised_model is not None:
            fv = fset.session_features.get("feature_vector_obj")
            if fv is not None:
                supervised_score = float(self.supervised_model.score(fv))
                if anomaly_score is not None:
                    effective_anomaly = round(
                        (1 - self.supervised_weight) * anomaly_score
                        + self.supervised_weight * supervised_score,
                        6,
                    )
                else:
                    effective_anomaly = supervised_score

        if self.variant == "A":
            risk = rules.rules_score
            contributions = {"rules": rules.rules_score}
            missing: list[str] = []
        else:
            fused: FusionResult = self.fusion.fuse(
                fset,
                anomaly_score=effective_anomaly,
                rules_score=rules.rules_score,
            )
            risk = fused.risk_score
            contributions = fused.contributions
            missing = fused.missing_components

        confidence = self.confidence_engine.assess(
            fset,
            risk_score=risk,
            rules_score=rules.rules_score,
            anomaly_score=anomaly_score,
        )

        severity = severity_from(
            SeverityInputs(
                risk_score=risk,
                confidence=confidence.confidence_score,
                sensitivity=fset.sensitivity_score.value,
                evidence_quality=self._evidence_quality(fset),
            )
        )

        return ScoredSession(
            session_id=fset.session_id,
            variant=self.variant,
            risk_score=risk,
            rules_score=rules.rules_score,
            anomaly_score=anomaly_score,
            supervised_score=supervised_score,
            confidence_score=confidence.confidence_score,
            confidence_state=confidence.state.value,
            severity=severity.value,
            contributions=contributions,
            missing_components=missing,
            fired_rules=list(rules.fired),
            model=self.version,
        )

    @staticmethod
    def _evidence_quality(fset: BehavioralFeatureSet) -> float | None:
        from algo.data_exfiltration.data_exfiltration.ml.feature_vector import FEATURE_NAMES

        availability = fset.feature_availability or {
            name: getattr(fset, name).availability.value for name in FEATURE_NAMES
        }
        available = sum(1 for v in availability.values() if v != FeatureAvailability.UNAVAILABLE.value)
        share = available / len(FEATURE_NAMES)
        return round(0.5 * share + 0.5 * float(fset.baseline_quality), 6)
