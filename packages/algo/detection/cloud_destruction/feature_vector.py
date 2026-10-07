"""Versioned ML feature vector — **Part 3**.

Turns the Part 2 :class:`~detection.cloud_destruction.features.SessionFeatureVector`
(plus its :class:`~detection.cloud_destruction.evidence.SessionEvidence`)
into a **versioned, ordered, numeric feature vector** for the anomaly and
supervised models.

Rules:

- The field order (:data:`FEATURE_ORDER`) and :data:`FEATURE_VERSION` are
  part of the model contract: a model trained on one version is never
  silently applied to another.
- Absent evidence maps to a **documented neutral default** (0.0 for
  anomaly-shaped features, 1.0 for recoverability) *and* is recorded in
  ``availability`` so downstream stages can weigh evidence honestly.
- ``business_criticality`` is ordinal-encoded (``unclassified``=0.0 …
  ``critical``=1.0) — a documented transform of an external catalog fact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from algo.detection.cloud_destruction.evidence import SessionEvidence
from algo.detection.cloud_destruction.features import SessionFeatureVector
from algo.detection.cloud_destruction.registry import FEATURE_VERSION
from algo.detection.cloud_destruction.schemas import BusinessCriticality

#: Ordered feature names — the model-facing contract (do not reorder lightly).
FEATURE_ORDER: tuple[str, ...] = (
    "write_rate_deviation",
    "modify_rate_deviation",
    "delete_rate_deviation",
    "delete_ratio",
    "rewrite_rate_deviation",
    "version_delete_rate",
    "delete_marker_rate",
    "snapshot_delete_rate",
    "backup_delete_rate",
    "recovery_point_delete_rate",
    "protection_degradation_score",
    "resource_scope_deviation",
    "actor_resource_novelty",
    "actor_operation_novelty",
    "mass_rewrite_transform_score",
    "temporal_anomaly",
    "business_criticality",
    "recoverability_score",
)

#: Neutral defaults for features whose evidence is absent.
NEUTRAL_DEFAULTS: dict[str, float] = {
    "recoverability_score": 1.0,  # unknown protection is not treated as destroyed
}
_DEFAULT_DEFAULT = 0.0

_CRITICALITY_ORDINAL: dict[str, float] = {
    "unclassified": 0.0,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}

__all__ = ["FEATURE_ORDER", "FEATURE_VERSION", "MLFeatureVector", "build_ml_feature_vector"]


@dataclass
class MLFeatureVector:
    """One versioned numeric feature vector with per-feature availability."""

    session_id: str
    values: dict[str, float]
    availability: dict[str, bool]
    feature_version: str = FEATURE_VERSION
    missing: tuple[str, ...] = ()

    def to_array(self) -> list[float]:
        return [self.values[name] for name in FEATURE_ORDER]

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "feature_version": self.feature_version,
            "values": {name: self.values[name] for name in FEATURE_ORDER},
            "missing": list(self.missing),
        }


def _value_of(vector: SessionFeatureVector, name: str) -> tuple[Optional[float], bool]:
    measured = getattr(vector, name, None)
    if measured is None:
        return None, False
    if not measured.available or measured.value is None:
        return None, False
    return float(measured.value), True


def build_ml_feature_vector(
    vector: SessionFeatureVector,
    evidence: SessionEvidence,
    hours: float,
) -> MLFeatureVector:
    """Build the numeric ML vector for one session.

    ``hours`` is the floored session span used for all rate features (the
    same value the Part 2 analyzers used, so rates stay consistent).
    """
    values: dict[str, float] = {}
    availability: dict[str, bool] = {}

    def put(name: str, value: Optional[float], present: bool) -> None:
        values[name] = (
            value if present else NEUTRAL_DEFAULTS.get(name, _DEFAULT_DEFAULT)
        )
        availability[name] = present

    # --- Part 2 deviations (already normalized to [0, 1]) -------------------
    for name in (
        "write_rate_deviation",
        "modify_rate_deviation",
        "delete_rate_deviation",
        "rewrite_rate_deviation",
        "resource_scope_deviation",
    ):
        value, present = _value_of(vector, name)
        put(name, value, present)

    # --- deletion mix ---------------------------------------------------------
    delete_ratio = evidence.delete_ratio
    put("delete_ratio", delete_ratio, delete_ratio is not None)

    # --- rates per hour (raw evidence, [0, inf) — models see raw rates) -------
    def rate(count: Optional[int]) -> tuple[float, bool]:
        if count is None or hours <= 0:
            return 0.0, False
        return count / hours, True

    v_rate, v_ok = rate(evidence.version_delete_events)
    put("version_delete_rate", v_rate, v_ok)
    marker_rate, marker_ok = rate(evidence.delete_marker_events)
    put("delete_marker_rate", marker_rate, marker_ok)
    snap_rate, snap_ok = rate(evidence.snapshot_delete_events)
    put("snapshot_delete_rate", snap_rate, snap_ok)
    backup_rate, backup_ok = rate(evidence.backup_delete_events)
    put("backup_delete_rate", backup_rate, backup_ok)
    rp_rate, rp_ok = rate(evidence.recovery_point_delete_events)
    put("recovery_point_delete_rate", rp_rate, rp_ok)

    # --- protection / recoverability / rewrite / temporal / novelty ------------
    value, present = _value_of(vector, "protection_degradation")
    put("protection_degradation_score", value, present)

    value, present = _value_of(vector, "actor_resource_novelty")
    put("actor_resource_novelty", value, present)
    value, present = _value_of(vector, "actor_operation_novelty")
    put("actor_operation_novelty", value, present)

    value, present = _value_of(vector, "rewrite_transform")
    put("mass_rewrite_transform_score", value, present)
    value, present = _value_of(vector, "temporal")
    put("temporal_anomaly", value, present)

    if vector.business_criticality is not None:
        put(
            "business_criticality",
            _CRITICALITY_ORDINAL.get(vector.business_criticality.value, 0.0),
            True,
        )
    else:
        put("business_criticality", None, False)

    value, present = _value_of(vector, "recoverability")
    put("recoverability_score", value, present)

    missing = tuple(name for name in FEATURE_ORDER if not availability.get(name))
    return MLFeatureVector(
        session_id=vector.session_id,
        values=values,
        availability=availability,
        feature_version=FEATURE_VERSION,
        missing=missing,
    )
