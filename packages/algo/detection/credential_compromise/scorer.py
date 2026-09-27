"""Risk fusion engine - **Part 2**.

Transparent, configuration-driven fusion of the ensemble scores::

    risk = w_behavior * behavior_score
         + w_rule      * rule_signal_score
         + w_anomaly   * anomaly_score
         + w_temporal  * temporal_score
         + w_privilege * privilege_score

The weights live in :class:`~detection.credential_compromise.config.FusionConfig`,
must sum to 1.0, and are *defaults to be calibrated on evaluation data* - they
are explicitly not claimed to be universally optimal. All component scores are
in ``[0, 1]``; fused risk is scaled to ``[0, 100]``.

Severity maps **risk + confidence + evidence quality** to LOW/MEDIUM/HIGH/
CRITICAL. A 90 with weak evidence is treated more cautiously than a 90 with
strong corroboration: weak evidence caps the achievable severity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from detection.credential_compromise.config import FusionConfig, ScoringConfig
from detection.credential_compromise.schemas import Severity

SEVERITY_NAMES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class ComponentScores:
    """The ensemble inputs, all in ``[0, 1]``."""

    behavior: float
    rule: float
    anomaly: float
    temporal: float
    privilege: float


@dataclass(frozen=True)
class FusionResult:
    """Full fusion output, kept for explainability."""

    risk: float                    # 0..100
    components: ComponentScores
    weights: dict[str, float]
    contributions: dict[str, float]


def rule_signal_score(signals: Sequence) -> float:
    """Rule signals -> [0, 1]. Bounded stacking: MEDIUM +, HIGH ++, CRIT +++."""
    if not signals:
        return 0.0
    per_severity = {"LOW": 0.05, "MEDIUM": 0.2, "HIGH": 0.35, "CRITICAL": 0.5}
    total = sum(per_severity.get(str(s.severity).upper(), 0.1) for s in signals)
    # Summing keeps corroboration meaningful but saturates so no stack of LOW
    # signals can masquerade as a CRITICAL hit.
    return round(min(1.0, total), 4)


def score_event(
    components: ComponentScores,
    *,
    config: FusionConfig,
) -> FusionResult:
    """Weighted fusion of the five component scores into risk 0-100."""
    weights = {
        "behavior": config.w_behavior,
        "rule": config.w_rule,
        "anomaly": config.w_anomaly,
        "temporal": config.w_temporal,
        "privilege": config.w_privilege,
    }
    raw = {
        "behavior": components.behavior,
        "rule": components.rule,
        "anomaly": components.anomaly * config.anomaly_confidence_discount,
        "temporal": components.temporal,
        "privilege": components.privilege,
    }
    contributions = {name: weights[name] * raw[name] for name in weights}
    risk01 = min(1.0, sum(contributions.values()))
    return FusionResult(
        risk=round(risk01 * 100.0, 2),
        components=components,
        weights=weights,
        contributions=contributions,
    )


def severity_for(
    risk: float,
    *,
    confidence: float = 1.0,
    corroborating_signals: int = 0,
) -> Severity:
    """Band (risk, confidence, evidence) into a :class:`Severity`.

    Weak evidence limits how high severity can climb: an uncorroborated 90
    with a cold-start baseline is capped below CRITICAL because the evidence
    does not yet justify the response a CRITICAL demands.
    """
    weak_evidence = confidence < 0.45 and corroborating_signals < 2
    if weak_evidence:
        return Severity.MEDIUM if risk >= 60.0 else Severity.LOW

    if risk >= 85.0:
        return Severity.CRITICAL
    if risk >= 70.0:
        return Severity.HIGH
    if risk >= 35.0:
        return Severity.MEDIUM
    return Severity.LOW


# --------------------------------------------------------------------------- #
# Dimensional scoring adapter (bridges the six-dimension behavioral layer)
# --------------------------------------------------------------------------- #


def calculate_risk(
    features,
    signals: Sequence = (),
    *,
    config: Optional[ScoringConfig] = None,
) -> float:
    """Confidence-weighted six-dimension behavioral score in [0, 100].

    Kept as the behavior-layer entry point; the full ensemble fusion lives in
    :func:`score_event`. Signal boosts come from ``ScoringConfig.signal_boost``
    (bounded stacking: the most severe signal wins).
    """
    config = config or ScoringConfig()
    dims = features.dimension_values()
    confidence_by_dimension = {
        "time": features.time_anomaly.confidence,
        "location": features.location_anomaly.confidence,
        "ip": features.network_anomaly.confidence,
        "device": features.device_anomaly.confidence,
        "api": features.api_anomaly.confidence,
        "privilege": features.privilege_anomaly.confidence,
    }
    total_weight = sum(config.weights.values()) or 1.0
    weighted_sum = sum(
        config.weights.get(name, 0.0) * value * confidence_by_dimension[name]
        for name, value in dims.items()
    )
    weighted_mean = weighted_sum / total_weight

    boost = 0.0
    for signal in signals:
        boost = max(boost, config.signal_boost.get(str(signal.severity).upper(), 0.0))
    return round(min(1.0, weighted_mean + boost / 100.0) * 100.0, 2)


__all__ = [
    "ComponentScores",
    "FusionResult",
    "calculate_risk",
    "rule_signal_score",
    "score_event",
    "severity_for",
]
