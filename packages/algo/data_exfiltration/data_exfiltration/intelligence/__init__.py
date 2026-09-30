"""Behavioral intelligence layer (Part 2).

Independent signal dimensions over the Part 1 foundation: volume,
destination, access pattern, sequence, sensitivity, time, actor-resource
relationship, and network egress — plus the multi-scope baseline engine
with cold-start support and baseline-poisoning protection.

This layer produces structured behavioral features. It still does NOT
produce a final risk verdict; fusion happens in Part 3.
"""

from __future__ import annotations

from .access_pattern_intelligence import (
    AccessPatternProfile,
    KnownAccessUniverse,
    access_pattern_score,
    access_pattern_signals,
    build_access_universe,
)
from .actor_resource_intelligence import (
    ActorResourceHistory,
    actor_resource_signals,
    build_actor_resource_history,
)
from .baseline_engine import BaselineEngine, BaselineSnapshot, Observation
from .baseline_guard import BaselinePoisoningPolicy, BaselineInfluence
from .destination_intelligence import (
    DestinationAssessment,
    KnownUniverse,
    assess_destinations,
)
from .egress_intelligence import EgressAssessment, egress_signals
from .feature_set import (
    AvailableFeature,
    BehavioralFeatureSet,
    FeatureAvailability,
    FEATURE_NAMES,
)
from .profiler import BehavioralProfileResult, BehavioralProfiler, IntelligenceContext
from .sensitivity_intelligence import SensitivityAssessment, sensitivity_signals
from .sequence import SequenceResult, score_sequence, session_action_sequence
from .time_intelligence import ApprovedSchedule, TimeAssessment, time_anomaly
from .volume_intelligence import VolumeDeviations, volume_deviations

__all__ = [
    "AccessPatternProfile",
    "ActorResourceHistory",
    "ApprovedSchedule",
    "AvailableFeature",
    "BaselineEngine",
    "BaselineInfluence",
    "BaselinePoisoningPolicy",
    "BaselineSnapshot",
    "BehavioralFeatureSet",
    "BehavioralProfileResult",
    "BehavioralProfiler",
    "DestinationAssessment",
    "EgressAssessment",
    "FEATURE_NAMES",
    "FeatureAvailability",
    "IntelligenceContext",
    "KnownAccessUniverse",
    "KnownUniverse",
    "Observation",
    "SensitivityAssessment",
    "SequenceResult",
    "TimeAssessment",
    "VolumeDeviations",
    "actor_resource_signals",
    "access_pattern_score",
    "access_pattern_signals",
    "assess_destinations",
    "build_access_universe",
    "build_actor_resource_history",
    "egress_signals",
    "score_sequence",
    "sensitivity_signals",
    "session_action_sequence",
    "time_anomaly",
    "volume_deviations",
]
