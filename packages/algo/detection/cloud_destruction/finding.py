"""Finding construction for destructive activity — **Part 3**.

Emits provider-neutral findings once risk and confidence exist. A finding
is the *auditable output* of the detector: risk + confidence + severity +
full model/version lineage.

Severity policy (never deletion count alone):

- derived from **risk, confidence, resource criticality, recoverability
  and evidence quality** via the versioned :class:`SeverityPolicy`;
- ``CRITICAL`` additionally requires strong evidence (confidence floor)
  and a destroyed-or-unknown recovery posture — loud-and-wrong findings
  are worse than quiet ones.

Every finding records: ``model_name``, ``model_version``,
``feature_version``, ``baseline_version``, ``scoring_version``,
``rule_version`` (plus confidence/severity versions) so any verdict can be
traced back to the exact detector configuration that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from algo.detection.cloud_destruction.baseline import BaselineQuality
from algo.detection.cloud_destruction.registry import (
    CONFIDENCE_VERSION,
    FEATURE_VERSION,
    RULE_VERSION,
    SCORING_VERSION,
    SEVERITY_VERSION,
    ModelRegistry,
)
from algo.detection.cloud_destruction.schemas import DestructiveActivitySession

__all__ = ["Severity", "SeverityPolicy", "DestructionFinding", "build_finding"]


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SeverityPolicy(BaseModel):
    """Versioned severity thresholds (risk × confidence matrix)."""

    model_config = ConfigDict(frozen=True)

    version: str = SEVERITY_VERSION

    medium_risk: float = 0.35
    high_risk: float = 0.6
    critical_risk: float = 0.8

    critical_confidence_floor: float = 0.4
    """CRITICAL requires at least this evidence confidence."""
    critical_needs_recovery_hit: bool = True
    """CRITICAL requires destroyed/low recoverability or unknown-with-critical."""

    def classify(
        self,
        risk: float,
        confidence: float,
        *,
        critical_resource: bool,
        recoverability: Optional[float],
        evidence_weight: float,
    ) -> Severity:
        """Map risk + context to a severity band."""
        if risk >= self.critical_risk:
            qualifies = confidence >= self.critical_confidence_floor
            recovery_ok = (
                (recoverability is not None and recoverability < 0.5)
                or (recoverability is None and critical_resource)
                or not self.critical_needs_recovery_hit
            )
            if qualifies and recovery_ok:
                return Severity.CRITICAL
            return Severity.HIGH
        if risk >= self.high_risk:
            return Severity.HIGH
        if risk >= self.medium_risk:
            return Severity.MEDIUM
        return Severity.LOW


@dataclass
class DestructionFinding:
    """Provider-neutral destructive-activity finding (audit-complete)."""

    finding_id: str
    session_id: str
    detector_name: str
    severity: Severity
    risk_score: float
    confidence_score: float

    actor_id: Optional[str]
    account_id: Optional[str]
    observed_at: Optional[datetime]

    # version stamps (spec-required)
    model_name: str
    model_version: str
    feature_version: str
    baseline_version: Optional[str]
    scoring_version: str
    rule_version: str
    confidence_version: str = CONFIDENCE_VERSION
    severity_version: str = SEVERITY_VERSION

    # context blocks
    risk_contributions: dict[str, Optional[float]] = field(default_factory=dict)
    confidence_factors: dict[str, float] = field(default_factory=dict)
    missing_evidence: tuple[str, ...] = ()
    approved_activity: Optional[dict[str, Any]] = None
    event_ids: tuple[str, ...] = ()
    resources_touched: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "session_id": self.session_id,
            "detector_name": self.detector_name,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "confidence_score": self.confidence_score,
            "actor_id": self.actor_id,
            "account_id": self.account_id,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "versions": {
                "model_name": self.model_name,
                "model_version": self.model_version,
                "feature_version": self.feature_version,
                "baseline_version": self.baseline_version,
                "scoring_version": self.scoring_version,
                "rule_version": self.rule_version,
                "confidence_version": self.confidence_version,
                "severity_version": self.severity_version,
            },
            "risk_contributions": self.risk_contributions,
            "confidence_factors": self.confidence_factors,
            "missing_evidence": list(self.missing_evidence),
            "approved_activity": self.approved_activity,
            "event_ids": list(self.event_ids),
            "resources_touched": list(self.resources_touched),
        }


def build_finding(
    session: DestructiveActivitySession,
    risk: "DestructionRisk",
    confidence: "ConfidenceResult",
    *,
    registry: Optional[ModelRegistry] = None,
    baseline_version: Optional[str] = None,
    baseline_quality: Optional[BaselineQuality] = None,
    anomaly_model_name: str = "rules_only",
    anomaly_model_version: str = "0",
    approved_activity: Optional[dict[str, Any]] = None,
    finding_id: Optional[str] = None,
    policy: Optional[SeverityPolicy] = None,
    recoverability: Optional[float] = None,
) -> DestructionFinding:
    """Build one finding from risk + confidence (+ session context)."""
    pol = policy or SeverityPolicy()
    reg = registry or ModelRegistry()

    # Recoverability for the severity policy must be passed explicitly by
    # the caller (extracted from the feature vector) — it is never guessed
    # from the fused contributions, which are already weighted and inverted.
    recoverability_value = recoverability

    critical = getattr(session, "critical_resource_touched", False)
    evidence_weight = sum(
        v for v in (risk.contributions or {}).values() if v is not None
    )
    severity = pol.classify(
        risk.risk_score,
        confidence.confidence_score,
        critical_resource=critical,
        recoverability=recoverability_value,
        evidence_weight=evidence_weight,
    )

    anomaly = reg.get("anomaly", anomaly_model_name)
    model_name = anomaly.model_name if anomaly else anomaly_model_name
    model_version = anomaly.model_version if anomaly else anomaly_model_version

    if finding_id is None:
        import uuid

        finding_id = str(uuid.uuid4())

    return DestructionFinding(
        finding_id=finding_id,
        session_id=session.session_id,
        detector_name="aegivion.cloud_destruction",
        severity=severity,
        risk_score=risk.risk_score,
        confidence_score=confidence.confidence_score,
        actor_id=session.actor_id,
        account_id=session.account_id,
        observed_at=session.end_time or session.start_time,
        model_name=model_name,
        model_version=model_version,
        feature_version=FEATURE_VERSION,
        baseline_version=baseline_version,
        scoring_version=SCORING_VERSION,
        rule_version=RULE_VERSION,
        risk_contributions=dict(risk.contributions or {}),
        confidence_factors=dict(confidence.factors or {}),
        missing_evidence=tuple(risk.missing_evidence),
        approved_activity=approved_activity,
        event_ids=tuple(session.event_ids),
        resources_touched=tuple(session.resources_touched),
        raw={
            "baseline_quality": baseline_quality.value if baseline_quality else None,
            "model_agreement": risk.model_agreement,
            "boosts_applied": list(risk.boosts_applied),
            "evidence_weight": evidence_weight,
        },
    )
