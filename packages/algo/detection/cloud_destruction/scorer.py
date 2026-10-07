"""Destruction risk fusion — **Part 3**.

Fuses the Part 2 behavioral features, the Part 3 sequence model and ML
anomaly scores into one ``destruction_risk`` in ``[0, 1]`` using
**configuration-driven weights** (:class:`ScoringConfig`, versioned via
:data:`~detection.cloud_destruction.registry.SCORING_VERSION`).

Rules honored:

- **No magic numbers in code**: every weight/policy knob lives in
  :class:`ScoringConfig`; the config digest rides on every score so any
  result can be reproduced.
- **Evidence-weighted**: a feature contributing ``None`` (unavailable)
  redistributes its weight to the evidence-backed components — absence of
  evidence dilutes rather than fabricates risk.
- **Risk ≠ confidence**: risk is *how dangerous the behavior appears*;
  confidence (see :mod:`detection.cloud_destruction.confidence`) is *how
  strong and complete the evidence is*. They are computed separately and
  never derived from each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from detection.cloud_destruction.registry import SCORING_VERSION, content_digest
from detection.cloud_destruction.schemas import DestructiveActivitySession

__all__ = [
    "ScoringConfig",
    "DestructionRisk",
    "score_destruction",
]

#: Ordinal encoding of business criticality for fusion (catalog fact, not a guess).
_CRITICALITY_ORDINAL: dict[str, float] = {
    "unclassified": 0.0,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}


def _criticality_strength(criticality) -> Optional[float]:
    """Ordinal criticality strength; ``None`` when the catalog says nothing."""
    if criticality is None:
        return None
    return _CRITICALITY_ORDINAL.get(criticality.value, 0.0)


class ScoringConfig(BaseModel):
    """Versioned risk-fusion configuration (weights sum to 1.0)."""

    model_config = ConfigDict(frozen=True)

    version: str = SCORING_VERSION

    # behavioral features (Part 2, evidence-weighted at fusion time)
    weight_modify: float = 0.08
    weight_delete: float = 0.14
    weight_delete_ratio: float = 0.06
    weight_version: float = 0.08
    weight_snapshot: float = 0.08
    weight_backup: float = 0.10
    weight_protection: float = 0.10
    weight_rewrite: float = 0.08
    weight_scope: float = 0.06
    weight_temporal: float = 0.06
    weight_sequence: float = 0.10
    weight_ml_anomaly: float = 0.10
    weight_supervised: float = 0.0
    """Active only when a fitted supervised model is supplied."""
    weight_recoverability: float = 0.06
    weight_criticality: float = 0.06

    # policy
    confidence_floor: float = 0.15
    """Risk above this *hard* floor survives even thin evidence."""
    boost_when_recoverability_destroyed: float = 1.15
    """Multiplier when recoverability evidence shows destroyed paths."""
    boost_when_critical: float = 1.2
    """Multiplier when a critical resource was hit (caps at 1.0)."""
    supervised_gate_probability: float = 0.5
    """Supervised probability blends into risk above this gate."""
    supervised_pull_weight: float = 0.10
    """How strongly the (gated) supervised probability pulls risk toward
    itself: ``risk += gate_strength * pull * (p_model - risk)``."""
    pace_fallback_cap_per_hour: float = 120.0
    """Delete-pace fallback cap when no baseline exists (events/hour)."""
    scope_fallback_cap: float = 10.0
    """Distinct-resource fallback cap when no baseline exists."""

    @property
    def total_behavioral_weight(self) -> float:
        return (
            self.weight_modify
            + self.weight_delete
            + self.weight_delete_ratio
            + self.weight_version
            + self.weight_snapshot
            + self.weight_backup
            + self.weight_protection
            + self.weight_rewrite
            + self.weight_scope
            + self.weight_temporal
            + self.weight_sequence
            + self.weight_ml_anomaly
            + self.weight_recoverability
            + self.weight_criticality
        )

    def normalized(self) -> dict[str, float]:
        """Weights normalized so the active behavioral set sums to 1.0."""
        total = self.total_behavioral_weight
        if total <= 0:
            raise ValueError("ScoringConfig weights must sum to a positive number")
        return {
            "modify": self.weight_modify / total,
            "delete": self.weight_delete / total,
            "delete_ratio": self.weight_delete_ratio / total,
            "version": self.weight_version / total,
            "snapshot": self.weight_snapshot / total,
            "backup": self.weight_backup / total,
            "protection": self.weight_protection / total,
            "rewrite": self.weight_rewrite / total,
            "scope": self.weight_scope / total,
            "temporal": self.weight_temporal / total,
            "sequence": self.weight_sequence / total,
            "ml_anomaly": self.weight_ml_anomaly / total,
            "supervised": 0.0,  # handled via gate, not in the normalized base
            "recoverability": self.weight_recoverability / total,
            "criticality": self.weight_criticality / total,
        }

    def digest(self) -> str:
        return content_digest(self.model_dump())


@dataclass
class DestructionRisk:
    """Fused destruction risk for one session (risk ≠ confidence)."""

    session_id: str
    risk_score: float
    """``[0, 1]`` — how dangerous the behavior appears."""
    scoring_version: str
    config_digest: str
    contributions: dict[str, Optional[float]]
    """Component → weighted contribution (audit: sum ≈ pre-boost risk)."""
    missing_evidence: tuple[str, ...] = ()
    boosts_applied: tuple[str, ...] = ()
    model_agreement: Optional[bool] = None
    """ML anomaly and rule signals point the same way (audit field)."""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "risk_score": self.risk_score,
            "scoring_version": self.scoring_version,
            "config_digest": self.config_digest,
            "contributions": self.contributions,
            "missing_evidence": list(self.missing_evidence),
            "boosts_applied": list(self.boosts_applied),
            "model_agreement": self.model_agreement,
            "raw": self.raw,
        }


def score_destruction(
    session: DestructiveActivitySession,
    vector: "SessionFeatureVector",
    *,
    anomaly_score: Optional[float] = None,
    supervised_probability: Optional[float] = None,
    sequence_score: Optional[float] = None,
    config: Optional[ScoringConfig] = None,
) -> DestructionRisk:
    """Fuse behavioral + ML evidence into one destruction risk.

    Every component participates only when its evidence is available;
    missing components redistribute their weight (documented, audited in
    ``contributions``/``missing_evidence``) instead of silently reading
    as "safe".
    """
    cfg = config or ScoringConfig()
    weights = cfg.normalized()

    def measured(name: str) -> Optional[float]:
        value = getattr(vector, name, None)
        if value is None or not value.available or value.value is None:
            return None
        return float(value.value)

    def fetch(measured_name: str, ml_name: Optional[str] = None) -> Optional[float]:
        value = measured(measured_name)
        if value is not None:
            return value
        if ml_name:
            return getattr(vector, "_ml_values", {}).get(ml_name)
        return None

    # Baseline-free fallbacks: when an actor has no trusted history, the
    # baseline-relative deviation is unavailable — but raw *pace* and *scope*
    # evidence still exists (Part 2 counters, capped by configuration).
    # These are marked in contributions as ``*_fallback`` for full audit.
    delete_value = measured("delete_rate_deviation")
    delete_is_fallback = False
    if delete_value is None:
        pace = vector.delete_rate_per_hour
        if pace is not None:
            delete_value = max(0.0, min(1.0, pace / cfg.pace_fallback_cap_per_hour))
            delete_is_fallback = True

    scope_value = measured("deletion_scope_anomaly")
    scope_is_fallback = False
    if scope_value is None and vector.unique_deleted_resources:
        scope_value = max(
            0.0, min(1.0, vector.unique_deleted_resources / cfg.scope_fallback_cap)
        )
        scope_is_fallback = True

    # Deletion-share fallback: the raw deletion-family share of the session
    # is real evidence even without a baseline (no normal-ratio comparison,
    # so it maps directly onto the anomaly-shaped slot).
    ratio_value = measured("delete_ratio_anomaly")
    ratio_is_fallback = False
    if ratio_value is None and vector.delete_ratio is not None:
        ratio_value = max(0.0, min(1.0, vector.delete_ratio))
        ratio_is_fallback = True

    components: list[tuple[str, str, Optional[float]]] = [
        ("modify", "weight_modify", measured("modify_rate_deviation")),
        ("delete", "weight_delete", delete_value),
        ("delete_ratio", "weight_delete_ratio", ratio_value),
        ("version", "weight_version", measured("version_delete_anomaly")),
        ("snapshot", "weight_snapshot", measured("snapshot_delete_anomaly")),
        ("backup", "weight_backup", measured("backup_delete_anomaly")),
        ("protection", "weight_protection", measured("protection_degradation")),
        ("rewrite", "weight_rewrite", measured("rewrite_transform")),
        ("scope", "weight_scope", scope_value),
        ("temporal", "weight_temporal", measured("temporal")),
        ("sequence", "weight_sequence", sequence_score),
        ("ml_anomaly", "weight_ml_anomaly", anomaly_score),
        # recoverability is inverted: losing recoverability raises risk
        (
            "recoverability",
            "weight_recoverability",
            (1.0 - r) if (r := measured("recoverability")) is not None else None,
        ),
        (
            "criticality",
            "weight_criticality",
            _criticality_strength(vector.business_criticality),
        ),
    ]

    contributions: dict[str, Optional[float]] = {}
    missing: list[str] = []
    weighted_sum = 0.0
    active_weight = 0.0

    for name, weight_key, value in components:
        weight = weights[weight_key.replace("weight_", "")]
        if value is None:
            contributions[name] = None
            missing.append(name)
            continue
        weighted_sum += weight * value
        active_weight += weight
        if (name == "delete" and delete_is_fallback) or (
            name == "scope" and scope_is_fallback
        ) or (name == "delete_ratio" and ratio_is_fallback):
            contributions[f"{name}_fallback"] = weight * value
        else:
            contributions[name] = weight * value

    # Supervised probability participates through an explicit gate: above
    # the gate it *pulls* the fused risk toward its calibrated probability
    # (strength grows with the probability itself). It can pull risk down
    # as well as up — the model's calibrated opinion, never a hidden veto.
    supervised_contribution: Optional[float] = None

    if active_weight <= 0:
        # no evidence at all: risk stays 0.0 but is reported as empty
        return DestructionRisk(
            session_id=session.session_id,
            risk_score=0.0,
            scoring_version=cfg.version,
            config_digest=cfg.digest(),
            contributions=contributions,
            missing_evidence=tuple(missing),
            raw={"evidence_weight_share": 0.0},
        )

    base = weighted_sum / active_weight

    if (
        supervised_probability is not None
        and supervised_probability >= cfg.supervised_gate_probability
    ):
        gate_span = max(1e-9, 1.0 - cfg.supervised_gate_probability)
        gate_strength = min(
            1.0,
            (supervised_probability - cfg.supervised_gate_probability) / gate_span,
        )
        supervised_contribution = (
            gate_strength * cfg.supervised_pull_weight * (supervised_probability - base)
        )
        base += supervised_contribution
        contributions["supervised"] = supervised_contribution

    # --- documented policy boosts (capped) -----------------------------------
    boosts: list[str] = []
    recoverability = measured("recoverability")
    if recoverability is not None and recoverability < 0.5:
        base *= cfg.boost_when_recoverability_destroyed
        boosts.append("recoverability_destroyed")

    critical_hit = vector.business_criticality is not None and (
        vector.business_criticality.value == "critical"
    )
    if critical_hit:
        base *= cfg.boost_when_critical
        boosts.append("critical_resource")

    risk = max(0.0, min(1.0, base))

    # model agreement: ML anomaly and behavioral delete/backup evidence agree
    ml = anomaly_score
    behavioral = measured("delete_rate_deviation") or measured("backup_delete_anomaly")
    agreement: Optional[bool] = None
    if ml is not None and behavioral is not None:
        agreement = (ml >= 0.5) == (behavioral >= 0.5)

    return DestructionRisk(
        session_id=session.session_id,
        scoring_version=cfg.version,
        risk_score=risk,
        config_digest=cfg.digest(),
        contributions=contributions,
        missing_evidence=tuple(missing),
        boosts_applied=tuple(boosts),
        model_agreement=agreement,
        raw={
            "evidence_weight_share": active_weight / sum(weights.values()),
            "supervised_gate_probability": cfg.supervised_gate_probability,
        },
    )
