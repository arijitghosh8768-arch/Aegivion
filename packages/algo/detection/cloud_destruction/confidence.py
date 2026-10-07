"""Evidence-based confidence calibration — **Part 3**.

Confidence answers: **how strong and complete is the evidence behind this
risk?** It is computed independently of risk and is *never* ``risk / 100``:

- risk = how dangerous the behavior appears;
- confidence = how much we trust the data and models behind that judgment.

Factors (all deterministic, configuration-weighted):

- **feature availability** — share of the versioned ML feature vector that
  carried real evidence (not neutral defaults);
- **telemetry completeness** — sessions built from event detail score
  higher than aggregate-only sessions;
- **baseline quality** — GOOD > LIMITED > INSUFFICIENT > NONE;
- **model agreement** — ML anomaly vs behavioral rules pointing the same
  way raises confidence; disagreement lowers it;
- **rule agreement** — how many behavioral components actively contributed
  to the fusion;
- **sequence consistency** — a non-trivial sequence-model signal present;
- **resource context** — known protection state / criticality enrichment.

A calibrated supervised model may *report* Brier/ECE (see
:mod:`detection.cloud_destruction.calibration`) but that never replaces
this evidence-based computation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from algo.detection.cloud_destruction.baseline import BaselineQuality
from algo.detection.cloud_destruction.registry import CONFIDENCE_VERSION, FEATURE_VERSION
from algo.detection.cloud_destruction.schemas import DestructiveActivitySession

__all__ = ["ConfidenceConfig", "ConfidenceResult", "compute_confidence"]


class ConfidenceConfig(BaseModel):
    """Versioned confidence weights (sum of active weights = 1.0)."""

    model_config = ConfigDict(frozen=True)

    version: str = CONFIDENCE_VERSION

    weight_availability: float = 0.30
    weight_telemetry: float = 0.15
    weight_baseline: float = 0.20
    weight_agreement: float = 0.15
    weight_rule_contribution: float = 0.10
    weight_sequence: float = 0.05
    weight_context: float = 0.05

    agreement_bonus: float = 0.1
    """Extra confidence when ML + rules agree (added inside the factor)."""
    disagreement_penalty: float = 0.5
    """Multiplier applied to the agreement factor when they disagree."""


#: Baseline quality → trust factor in ``[0, 1]``.
BASELINE_TRUST: dict[str, float] = {
    BaselineQuality.GOOD.value: 1.0,
    BaselineQuality.LIMITED.value: 0.6,
    BaselineQuality.INSUFFICIENT.value: 0.25,
    BaselineQuality.NONE.value: 0.0,
}


@dataclass
class ConfidenceResult:
    """Evidence-based confidence for one scored session."""

    session_id: str
    confidence_score: float
    confidence_version: str
    factors: dict[str, float]
    """Factor → value in ``[0, 1]`` (audit block)."""
    missing_evidence: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "confidence_score": self.confidence_score,
            "confidence_version": self.confidence_version,
            "factors": self.factors,
            "missing_evidence": list(self.missing_evidence),
            "raw": self.raw,
        }


def compute_confidence(
    session: DestructiveActivitySession,
    vector: "SessionFeatureVector",
    risk: "DestructionRisk",
    *,
    ml_vector: Optional["MLFeatureVector"] = None,
    baseline_quality: Optional[BaselineQuality] = None,
    has_event_detail: bool = False,
    model_agreement: Optional[bool] = None,
    supervised_report: Optional["CalibrationReport"] = None,
    config: Optional[ConfidenceConfig] = None,
) -> ConfidenceResult:
    """Compute evidence-based confidence for one session's risk.

    ``supervised_report`` (Brier/ECE) is *reported*, not fused: calibration
    quality documents model trustworthiness but does not manufacture
    evidence.
    """
    cfg = config or ConfidenceConfig()

    # 1) feature availability from the versioned ML vector
    if ml_vector is not None:
        present = sum(1 for v in ml_vector.availability.values() if v)
        availability_factor = present / max(1, len(ml_vector.availability))
        missing_from_vector = tuple(ml_vector.missing)
    else:
        availability_factor = 0.0
        missing_from_vector = ()

    # 2) telemetry completeness: event detail vs aggregate-only
    telemetry_factor = 1.0 if has_event_detail else 0.4

    # 3) baseline quality trust
    baseline_factor = BASELINE_TRUST.get(
        baseline_quality.value if baseline_quality else BaselineQuality.NONE.value,
        0.0,
    )

    # 4) model agreement (ML vs behavioral)
    if model_agreement is True:
        agreement_factor = 1.0
    elif model_agreement is False:
        agreement_factor = cfg.disagreement_penalty
    else:
        agreement_factor = 0.5  # unknown: neutral, not trusting

    # 5) rule contribution: share of fusion components that had evidence
    contributions = risk.contributions or {}
    scored = [v for v in contributions.values() if v is not None]
    if contributions:
        rule_factor = len(scored) / len(contributions)
    else:
        rule_factor = 0.0

    # 6) sequence consistency: sequence evidence present in the fusion
    sequence_factor = 1.0 if contributions.get("sequence") is not None else 0.0

    # 7) resource context: criticality and/or recoverability enrichment known
    context_signals = 0
    context_total = 2
    if vector.business_criticality is not None:
        context_signals += 1
    if vector.recoverability is not None and vector.recoverability.available:
        context_signals += 1
    context_factor = context_signals / context_total

    factors = {
        "feature_availability": availability_factor,
        "telemetry_completeness": telemetry_factor,
        "baseline_quality": baseline_factor,
        "model_agreement": agreement_factor,
        "rule_contribution": rule_factor,
        "sequence_consistency": sequence_factor,
        "resource_context": context_factor,
    }
    weights = {
        "feature_availability": cfg.weight_availability,
        "telemetry_completeness": cfg.weight_telemetry,
        "baseline_quality": cfg.weight_baseline,
        "model_agreement": cfg.weight_agreement,
        "rule_contribution": cfg.weight_rule_contribution,
        "sequence_consistency": cfg.weight_sequence,
        "resource_context": cfg.weight_context,
    }
    total_weight = sum(weights.values())

    score = sum(
        weights[name] * factors[name] for name in weights
    ) / total_weight

    # agreement bonus/penalty inside the factor keeps weights interpretable
    if model_agreement is True:
        score = min(1.0, score + cfg.agreement_bonus * cfg.weight_agreement)

    missing = tuple(name for name, factor in factors.items() if factor <= 0.0)
    return ConfidenceResult(
        session_id=session.session_id,
        confidence_score=max(0.0, min(1.0, score)),
        confidence_version=cfg.version,
        factors=factors,
        missing_evidence=missing,
        raw={
            "supervised_calibration": supervised_report.to_log_dict() if supervised_report else None,
            "feature_version": FEATURE_VERSION,
            "has_event_detail": has_event_detail,
        },
    )
