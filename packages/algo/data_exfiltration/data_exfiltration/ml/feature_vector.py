"""ML feature vector construction from Part 2 behavioral features.

Rules:

- STABLE FEATURE ORDER: the vector layout is frozen by ``FEATURE_NAMES``;
  models, evaluation artifacts, and future re-scoring all depend on it.
- Only features that exist in the real telemetry path are used. A feature
  the pipeline cannot produce is not invented here.
- Availability is part of the vector: unavailable features are masked
  (0.0 value + 0.0 availability) so models and fusion can distinguish
  "measured zero" from "not measurable".
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    BehavioralFeatureSet,
    FeatureAvailability,
)

FEATURE_VERSION = "ml-features-1.0.0"

# Frozen feature order (spec list). Keep in sync with tests.
FEATURE_NAMES: tuple[str, ...] = (
    "volume_deviation",
    "object_deviation",
    "request_rate_deviation",
    "resource_diversity",
    "destination_novelty",
    "asn_novelty",
    "country_novelty",
    "provider_novelty",
    "resource_novelty",
    "prefix_novelty",
    "access_sequence_score",
    "time_anomaly",
    "actor_resource_novelty",
    "sensitivity_score",
    "sensitivity_confidence",
    "network_egress_bytes",
    "external_egress_ratio",
)

# Mapping: spec feature -> (BehavioralFeatureSet attribute, detail key)
_FEATURE_SOURCES: dict[str, tuple[str, str | None]] = {
    "volume_deviation": ("volume_score", None),
    "object_deviation": ("object_count_score", None),
    "request_rate_deviation": ("request_rate_score", None),
    "resource_diversity": ("access_pattern_score", "access_diversity"),
    "destination_novelty": ("destination_score", "destination_novelty"),
    "asn_novelty": ("destination_score", "asn_novelty"),
    "country_novelty": ("destination_score", "country_novelty"),
    "provider_novelty": ("destination_score", "provider_novelty"),
    "resource_novelty": ("access_pattern_score", "resource_novelty"),
    "prefix_novelty": ("access_pattern_score", "prefix_novelty"),
    "access_sequence_score": ("access_pattern_score", "access_sequence_score"),
    "time_anomaly": ("time_score", None),
    "actor_resource_novelty": ("actor_resource_score", None),
    "sensitivity_score": ("sensitivity_score", None),
    "sensitivity_confidence": ("sensitivity_score", "__confidence__"),
    "network_egress_bytes": ("egress_score", "network_egress_bytes"),
    "external_egress_ratio": ("egress_score", "external_egress_ratio"),
}


class MLFeatureVector(BaseModel):
    """A versioned, ordered feature vector with availability mask."""

    subject_id: str
    session_id: str
    computed_at_epoch_ms: float
    values: dict[str, float | None] = Field(default_factory=dict)
    """None = feature unavailable (never fabricated to 0)."""
    availability: dict[str, str] = Field(default_factory=dict)
    feature_version: str = FEATURE_VERSION

    def ordered_values(self) -> list[float]:
        """Vector in frozen FEATURE_NAMES order; unavailable -> 0.0 (masked)."""
        return [
            float(self.values.get(name) or 0.0) if self.values.get(name) is not None else 0.0
            for name in FEATURE_NAMES
        ]

    def availability_mask(self) -> list[float]:
        """1.0 where the feature was available, 0.0 where not (same order)."""
        return [
            1.0 if self.availability.get(name) != FeatureAvailability.UNAVAILABLE.value else 0.0
            for name in FEATURE_NAMES
        ]

    def available_count(self) -> int:
        return sum(1 for name in FEATURE_NAMES if self.availability.get(name) != FeatureAvailability.UNAVAILABLE.value)


def _value_from(feature, detail_key: str | None) -> float | None:
    if feature is None:
        return None
    if detail_key == "__confidence__":
        return getattr(feature, "provenance", None) and None  # placeholder, replaced below
    if detail_key is None:
        return feature.value
    value = feature.detail.get(detail_key)
    return float(value) if isinstance(value, (int, float)) else None


def build_feature_vector(
    fset: BehavioralFeatureSet,
    *,
    subject_id: str | None = None,
) -> MLFeatureVector:
    """Build the ML feature vector from a BehavioralFeatureSet."""
    values: dict[str, float | None] = {}
    availability: dict[str, str] = {}

    for name in FEATURE_NAMES:
        attr, detail_key = _FEATURE_SOURCES[name]
        feature = getattr(fset, attr, None)
        if feature is None:
            values[name] = None
            availability[name] = FeatureAvailability.UNAVAILABLE.value
            continue

        if detail_key == "__confidence__":
            # sensitivity_confidence: the confidence grade of the winning
            # sensitivity contribution, from the feature's detail block
            conf = None
            contributions = (feature.detail or {}).get("contributions") or []
            if contributions:
                conf = contributions[0].get("confidence")
            grade = {"observed": 1.0, "external_enrichment": 0.9, "estimated": 0.5}
            values[name] = grade.get(str(conf), 0.5 if conf else None)
            availability[name] = (
                feature.availability.value if feature.value is not None
                else FeatureAvailability.UNAVAILABLE.value
            )
            continue

        value = _value_from(feature, detail_key)
        values[name] = value
        availability[name] = feature.availability.value

    return MLFeatureVector(
        subject_id=subject_id or fset.subject_id,
        session_id=fset.session_id,
        computed_at_epoch_ms=fset.computed_at_epoch_ms,
        values=values,
        availability=availability,
    )
