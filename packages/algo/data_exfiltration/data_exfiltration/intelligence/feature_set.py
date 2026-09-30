"""Structured behavioral feature output.

Every session profiled by the intelligence layer yields a
:class:`BehavioralFeatureSet`. Each dimension feature is an
:class:`AvailableFeature` carrying value + availability + provenance, so
downstream fusion (Part 3) can distinguish "measured and normal" from
"unmeasurable" — never fabricating evidence.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

FEATURE_NAMES = (
    "volume_score",
    "object_count_score",
    "request_rate_score",
    "destination_score",
    "access_pattern_score",
    "sensitivity_score",
    "time_score",
    "actor_resource_score",
    "egress_score",
)


class FeatureAvailability(str, Enum):
    """Whether a feature could be honestly computed."""

    OBSERVED = "observed"        # computed from sufficient real history
    ESTIMATED = "estimated"      # computed from peer/cold-start fallback
    UNAVAILABLE = "unavailable"  # telemetry or history missing; value not fabricated


class AvailableFeature(BaseModel):
    """One behavioral feature value with its evidence status."""

    value: float | None = None
    availability: FeatureAvailability = FeatureAvailability.UNAVAILABLE
    provenance: str | None = None
    """Where the comparison history came from, e.g. ``personal:30d``,
    ``peer:analytics``, ``cold_start``, ``observation``."""
    detail: dict = Field(default_factory=dict)
    """Per-component breakdown for human review and Part 3 fusion."""


class BehavioralFeatureSet(BaseModel):
    """All behavioral features for one session."""

    subject_id: str
    session_id: str
    actor_id: str | None = None
    computed_at_epoch_ms: float

    volume_score: AvailableFeature = Field(default_factory=AvailableFeature)
    object_count_score: AvailableFeature = Field(default_factory=AvailableFeature)
    request_rate_score: AvailableFeature = Field(default_factory=AvailableFeature)
    destination_score: AvailableFeature = Field(default_factory=AvailableFeature)
    access_pattern_score: AvailableFeature = Field(default_factory=AvailableFeature)
    sensitivity_score: AvailableFeature = Field(default_factory=AvailableFeature)
    time_score: AvailableFeature = Field(default_factory=AvailableFeature)
    actor_resource_score: AvailableFeature = Field(default_factory=AvailableFeature)
    egress_score: AvailableFeature = Field(default_factory=AvailableFeature)

    baseline_quality: float = 0.0
    """0..1: how much trusted history backed this profile (1 = warm personal)."""
    baseline_scope_used: str = "none"
    """``personal`` | ``peer`` | ``none``."""
    cold_start: bool = False

    feature_availability: dict[str, str] = Field(default_factory=dict)
    feature_provenance: dict[str, str] = Field(default_factory=dict)

    session_features: dict = Field(default_factory=dict)
    """Slot for downstream ML payloads (e.g. the frozen feature vector
    built by algo.data_exfiltration.data_exfiltration.ml.feature_vector)."""

    def finalize(self) -> "BehavioralFeatureSet":
        """Fill the availability/provenance maps from the named features."""
        for name in FEATURE_NAMES:
            feature: AvailableFeature = getattr(self, name)
            self.feature_availability[name] = feature.availability.value
            self.feature_provenance[name] = feature.provenance or ""
        return self
