"""Rule policy: transparent, evidence-weighted signal combination.

This is NOT a risk verdict machine — it is the rules component used by
the fusion engine and by variants A/B of the evaluation harness. Every
component is a documented rule over behavioral features; the mapping
from evidence to contribution is monotone and readable.
"""

from __future__ import annotations

from typing import Any, Mapping

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    BehavioralFeatureSet,
    FeatureAvailability,
)

# Rule parameters (documented, configuration-ready; not "optimal" claims)
_ENUMERATION_RATIO = 0.8
_ENUMERATION_COUNT = 10
_HIGH_RISK_DEST_CLASS = "high_risk_external"
_UNKNOWN_EXTERNAL = "unknown_external"
_NOVELTY_MEDIUM = 0.4
_NOVELTY_HIGH = 0.8
_TIME_HIGH = 0.5
_CROSS_BU_WEIGHT = 0.2


class RuleAssessment(BaseModel):
    rules_score: float
    """0..1 transparent rule combination (not a probability)."""
    contributions: dict[str, float] = Field(default_factory=dict)
    fired: list[str] = Field(default_factory=list)


class RulePolicy:
    """Deterministic rules over the behavioral feature set."""

    def __init__(self, params: Mapping[str, float] | None = None) -> None:
        self._p = dict(params or {})

    def _param(self, key: str, default: float) -> float:
        return float(self._p.get(key, default))

    def evaluate(self, fset: BehavioralFeatureSet) -> RuleAssessment:
        contributions: dict[str, float] = {}
        fired: list[str] = []

        def _val(feat) -> float | None:
            if feat is None or feat.value is None:
                return None
            return float(feat.value)

        volume = _val(fset.volume_score)
        object_dev = _val(fset.object_count_score)
        request_rate = _val(fset.request_rate_score)
        destination = _val(fset.destination_score)
        access = _val(fset.access_pattern_score)
        sensitivity = _val(fset.sensitivity_score)
        time_anom = _val(fset.time_score)
        actor_res = _val(fset.actor_resource_score)
        egress = _val(fset.egress_score)

        # R1: volume/object/request deviations (only when individually available)
        volume_family = [v for v in (volume, object_dev, request_rate) if v is not None]
        if volume_family:
            contributions["volume_family"] = max(volume_family)
            if max(volume_family) >= 0.5:
                fired.append("volume_deviation_elevated")

        # R2: destination novelty/classification
        dest_detail = fset.destination_score.detail or {}
        worst_class = dest_detail.get("worst_class")
        if worst_class == _HIGH_RISK_DEST_CLASS:
            contributions["destination_class"] = 1.0
            fired.append("high_risk_destination")
        elif worst_class == _UNKNOWN_EXTERNAL and (destination or 0) >= self._param("novelty_medium", _NOVELTY_MEDIUM):
            contributions["destination_class"] = 0.6
            fired.append("unknown_external_destination")
        elif destination is not None:
            contributions["destination_class"] = 0.2 * min(1.0, destination)

        # R3: enumeration pattern (many objects across few prefixes)
        access_detail = fset.access_pattern_score.detail or {}
        if access_detail.get("unique_objects") is not None and access_detail.get("unique_prefixes") is not None:
            total = float(access_detail.get("unique_objects") or 0)
            prefixes = float(access_detail.get("unique_prefixes") or 0)
            if total > 0 and prefixes / total >= self._param("enumeration_ratio", _ENUMERATION_RATIO) \
                    and total >= self._param("enumeration_count", _ENUMERATION_COUNT):
                contributions["enumeration"] = 0.7
                fired.append("enumeration_pattern")

        # R4: access-pattern novelty + structural pattern evidence
        if access is not None:
            contributions["access_novelty"] = access
            if access >= self._param("novelty_high", _NOVELTY_HIGH):
                fired.append("access_pattern_novel")

        # R5: sensitivity raised to evidence, not verdict
        if sensitivity is not None and sensitivity >= 0.55:
            contributions["sensitivity"] = 0.3 * sensitivity
            fired.append("sensitive_data_access")

        # R6: time anomaly
        if time_anom is not None:
            contributions["time"] = 0.4 * time_anom
            if time_anom >= self._param("time_high", _TIME_HIGH):
                fired.append("unusual_time")

        # R7: actor-resource novelty
        if actor_res is not None:
            contributions["actor_resource"] = actor_res
            if actor_res >= self._param("novelty_high", _NOVELTY_HIGH):
                fired.append("unexpected_actor_resource")

        # R8: egress evidence (only when measured)
        if egress is not None and egress > 0:
            contributions["egress"] = egress
            if egress >= 0.5:
                fired.append("high_egress_ratio")

        # transparent aggregation: capped weighted max
        # (max keeps any single strong signal visible; cap bounds the sum)
        score = 0.0
        weights = {
            "volume_family": 1.0, "destination_class": 0.9, "enumeration": 0.7,
            "access_novelty": 0.6, "sensitivity": 0.5, "time": 0.5,
            "actor_resource": 0.6, "egress": 0.8,
        }
        for key, contribution in contributions.items():
            score = max(score, contributions[key])
        weighted = sum(contributions[k] * w for k, w in weights.items() if k in contributions)
        score = min(1.0, 0.6 * score + 0.4 * min(1.0, weighted / 3.0))

        return RuleAssessment(
            rules_score=round(score, 4),
            contributions=contributions,
            fired=fired,
        )
