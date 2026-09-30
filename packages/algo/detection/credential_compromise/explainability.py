"""Explainability structure - **Part 3 (ARDE)**.

Produces the machine-readable explanation attached to every finding:
``top_contributors``, ``supporting_evidence``, ``contradicting_evidence``,
``baseline_quality`` and ``model_agreement``. Everything is derived from the
actual feature vector, rule signals and ARDE result - no prose is invented
here, and a future LLM layer may only *render* this structure, never
fabricate evidence.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from algo.detection.credential_compromise.arde import ArdeResult
from algo.detection.credential_compromise.features import BehavioralFeatures
from algo.detection.credential_compromise.schemas import BaselineQuality

#: Human-readable labels for feature names (used in top_contributors).
FEATURE_LABELS: dict[str, str] = {
    "time_anomaly": "Unusual activity hour",
    "country_novelty": "New country",
    "region_novelty": "New region",
    "location_anomaly": "Unusual location",
    "ip_novelty": "New source IP",
    "asn_novelty": "New ASN",
    "network_anomaly": "Unusual network",
    "client_novelty": "New client",
    "device_anomaly": "Unusual device",
    "api_novelty": "Rare API",
    "service_novelty": "Unusual service",
    "api_frequency_deviation": "Unusual API frequency",
    "read_write_deviation": "Unusual read/write mix",
    "api_sequence_deviation": "Unusual API sequence",
    "privilege_anomaly": "Privilege modification",
    "mfa_anomaly": "MFA state anomaly",
    "network_reputation": "Network reputation",
}

SIGNAL_LABELS: dict[str, str] = {
    "R001": "New country",
    "R002": "New region",
    "R003": "New IP",
    "R004": "New ASN",
    "R005": "Unusual activity hour",
    "R006": "New client",
    "R007": "Rare API",
    "R008": "Unusual service",
    "R009": "Unusual API frequency",
    "R010": "Privilege modification",
    "R011": "Suspicious role assumption",
    "R012": "Access-key behavior anomaly",
    "R013": "MFA state anomaly",
    "R014": "Unusual burst of API activity",
}


class Explanation(BaseModel):
    """Machine-readable explanation payload for one finding."""

    model_config = ConfigDict(frozen=True)

    top_contributors: tuple[str, ...] = ()
    supporting_evidence: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    contradicting_evidence: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    baseline_quality: str = BaselineQuality.COLD_START.value
    model_agreement: str = "NOT_ASSESSED"   # FULL | PARTIAL | NONE | NOT_ASSESSED
    robustness_score: float = 100.0
    validation_status: str = "PASSED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "top_contributors": list(self.top_contributors),
            "supporting_evidence": [dict(e) for e in self.supporting_evidence],
            "contradicting_evidence": [dict(e) for e in self.contradicting_evidence],
            "baseline_quality": self.baseline_quality,
            "model_agreement": self.model_agreement,
            "robustness_score": self.robustness_score,
            "validation_status": self.validation_status,
        }


def model_agreement(
    signals: Sequence[dict[str, Any]],
    anomaly_score: Optional[float],
    anomaly_model_used: bool,
) -> str:
    """Classify rule-vs-ML agreement.

    ``FULL`` - both layers point the same way; ``PARTIAL`` - one layer silent
    or mildly disagreeing; ``NONE`` - direct contradiction (rules high, ML
    normal or vice versa); ``NOT_ASSESSED`` - no ML in the loop.
    """
    if not anomaly_model_used or anomaly_score is None:
        return "NOT_ASSESSED"
    rule_score = 0.0
    severity_weight = {"LOW": 0.15, "MEDIUM": 0.4, "HIGH": 0.8, "CRITICAL": 1.0}
    for signal in signals:
        rule_score = max(rule_score, severity_weight.get(str(signal.get("severity", "")).upper(), 0.0))
    gap = abs(rule_score - float(anomaly_score))
    if gap <= 0.25:
        return "FULL"
    if gap <= 0.55:
        return "PARTIAL"
    return "NONE"


def build_explanation(
    features: BehavioralFeatures,
    signals: Sequence[dict[str, Any]],
    arde_result: Optional[ArdeResult],
    *,
    anomaly_score: Optional[float] = None,
    anomaly_model_used: bool = False,
    top_k: int = 5,
) -> Explanation:
    """Assemble the explanation from actual evidence. Deterministic."""
    supporting: list[dict[str, Any]] = []
    contradicting: list[dict[str, Any]] = []

    # Features at or above the attention threshold are supporting evidence;
    # confident features at zero are contradicting evidence.
    for name, feature in features.all_features().items():
        if feature.value >= 0.5:
            supporting.append(
                {
                    "feature": name,
                    "label": FEATURE_LABELS.get(name, name),
                    "value": round(feature.value, 4),
                    "confidence": round(feature.confidence, 4),
                }
            )
        elif feature.value <= 0.05 and feature.confidence >= 0.5:
            contradicting.append(
                {
                    "feature": name,
                    "label": FEATURE_LABELS.get(name, name),
                    "value": round(feature.value, 4),
                    "confidence": round(feature.confidence, 4),
                    "note": "well-baselined dimension shows nothing unusual",
                }
            )

    for signal in signals:
        supporting.append(
            {
                "rule_id": signal.get("rule_id"),
                "label": SIGNAL_LABELS.get(str(signal.get("rule_id")), str(signal.get("signal", ""))),
                "severity": str(signal.get("severity", "")).lower(),
                "value": signal.get("value"),
            }
        )

    # Top contributors: fired signals first (strongest value, then most
    # severe), then the strongest features, capped at top_k.
    severity_weight = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    contributors: list[str] = []
    for signal in sorted(
        signals,
        key=lambda s: (
            float(s.get("value", 0.0)),
            severity_weight.get(str(s.get("severity", "")).upper(), 0),
        ),
        reverse=True,
    ):
        label = SIGNAL_LABELS.get(str(signal.get("rule_id")), str(signal.get("signal", "")))
        if label and label not in contributors:
            contributors.append(label)
    strongest = sorted(
        features.all_features().items(), key=lambda kv: kv[1].value, reverse=True
    )
    for name, feature in strongest:
        if len(contributors) >= top_k:
            break
        if feature.value >= 0.5:
            label = FEATURE_LABELS.get(name, name)
            if label not in contributors:
                contributors.append(label)
    contributors = contributors[:top_k]

    baseline_quality = features.baseline_quality.value
    agreement = model_agreement(signals, anomaly_score, anomaly_model_used)

    return Explanation(
        top_contributors=tuple(contributors),
        supporting_evidence=tuple(supporting),
        contradicting_evidence=tuple(contradicting),
        baseline_quality=baseline_quality,
        model_agreement=agreement,
        robustness_score=arde_result.robustness_score if arde_result else 100.0,
        validation_status=arde_result.validation_status if arde_result else "PASSED",
    )


__all__ = ["Explanation", "build_explanation", "model_agreement"]
