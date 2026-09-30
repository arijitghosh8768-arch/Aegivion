"""Interpretable weighted risk fusion.

    risk = w_volume * volume
         + w_destination * destination
         + w_access * access_pattern
         + w_sensitivity * sensitivity
         + w_time * time
         + w_actor_resource * actor_resource
         + w_egress * egress
         + w_anomaly * anomaly

Design rules:

- Weights are CONFIGURATION-DRIVEN and VERSIONED. Defaults encode the
  Aegivion working hypothesis and are NOT claimed to be optimal.
- Unavailable features are EXCLUDED and the weight vector is renormalized
  over what is actually available; the result records which features
  contributed so analysts see the basis of every score.
- Risk is NOT confidence: this module outputs risk only. Confidence is a
  separate engine (confidence_engine.py) and the two are never merged.
- Weight vectors are content-versioned: identical weights -> identical
  version id, any edit -> new version.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    BehavioralFeatureSet,
    FeatureAvailability,
)


class FusionWeights(BaseModel):
    """Versioned fusion weights (configuration-driven)."""

    volume: float = 0.20
    destination: float = 0.15
    access_pattern: float = 0.12
    sensitivity: float = 0.10
    time: float = 0.08
    actor_resource: float = 0.10
    egress: float = 0.15
    anomaly: float = 0.10

    def as_dict(self) -> dict[str, float]:
        return self.model_dump()

    def version_id(self) -> str:
        blob = json.dumps(self.as_dict(), sort_keys=True).encode()
        return "fw-" + hashlib.sha256(blob).hexdigest()[:12]


class FusionResult(BaseModel):
    """Interpretable fusion output for one session."""

    session_id: str
    risk_score: float
    contributions: dict[str, float] = Field(default_factory=dict)
    """component -> weighted contribution (available components only)"""
    missing_components: list[str] = Field(default_factory=list)
    weights_version: str
    renormalized: bool = False
    detail: dict[str, Any] = Field(default_factory=dict)


class WeightedFusionEngine:
    """Config-driven, versioned, interpretable risk fusion."""

    engine_id = "weighted_fusion"

    def __init__(self, weights: FusionWeights | None = None) -> None:
        self._weights = weights or FusionWeights()

    @property
    def weights(self) -> FusionWeights:
        return self._weights

    @property
    def weights_version(self) -> str:
        return self._weights.version_id()

    def fuse(
        self,
        fset: BehavioralFeatureSet,
        *,
        anomaly_score: float | None = None,
        rules_score: float | None = None,
    ) -> FusionResult:
        """Fuse behavioral features (+ optional anomaly/rules) into risk.

        ``rules_score`` does not add a separate term; it is recorded in
        detail for the harness. ``anomaly_score`` is the ML component
        (variant C/D). When the anomaly feature is unavailable (no fitted
        model), its weight is renormalized away — the fusion never
        pretends an ML opinion exists.
        """
        # component -> (value, available?)
        components: dict[str, tuple[float | None, bool]] = {
            "volume": (self._value(fset.volume_score), fset.volume_score.value is not None),
            "destination": (self._value(fset.destination_score), fset.destination_score.value is not None),
            "access_pattern": (self._value(fset.access_pattern_score), fset.access_pattern_score.value is not None),
            "sensitivity": (self._value(fset.sensitivity_score), fset.sensitivity_score.value is not None),
            "time": (self._value(fset.time_score), fset.time_score.value is not None),
            "actor_resource": (self._value(fset.actor_resource_score), fset.actor_resource_score.value is not None),
            "egress": (self._value(fset.egress_score), fset.egress_score.value is not None),
            "anomaly": (anomaly_score, anomaly_score is not None),
        }

        weights = self._weights.as_dict()
        available = {k: v for k, (v, ok) in components.items() if ok and v is not None}
        missing = [k for k, (_v, ok) in components.items() if not ok]

        total_weight = sum(weights[k] for k in available)
        contributions: dict[str, float] = {}
        risk = 0.0
        renormalized = abs(total_weight - 1.0) > 1e-9
        if total_weight > 0:
            for name, value in sorted(available.items()):
                share = weights[name] / total_weight
                contributions[name] = round(value * share, 6)
                risk += value * share

        return FusionResult(
            session_id=fset.session_id,
            risk_score=round(min(1.0, max(0.0, risk)), 4),
            contributions=contributions,
            missing_components=missing,
            weights_version=self.weights_version,
            renormalized=renormalized,
            detail={
                "rules_score": rules_score,
                "available_components": sorted(available),
                "weights": {k: weights[k] for k in sorted(available)},
            },
        )

    @staticmethod
    def _value(feature) -> float | None:
        if feature is None or feature.value is None:
            return None
        return float(feature.value)
