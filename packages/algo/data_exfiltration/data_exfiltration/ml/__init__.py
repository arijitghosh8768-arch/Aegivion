"""Part 3: ML + risk-fusion layer.

Everything here consumes the Part 2 behavioral features and produces
risk scores, confidence assessments, and severities. Principles:

- ML must EARN its place: the harness compares rules-only (A),
  rules+baseline (B), +Isolation Forest (C), and the full model (D)
  and measures whether each addition helps.
- Risk is not confidence. Two separate outputs, two separate engines.
- No fabricated labels: supervised paths only run on data explicitly
  marked as labeled, and synthetic data stays marked synthetic.
- Temporal splits only: future events never leak into training.
- Determinism: fixed seeds, stable feature order, sorted iteration.
"""

from __future__ import annotations

from .confidence_engine import (
    ConfidenceAssessment,
    ConfidenceEngine,
    ConfidenceState,
    FindingConfidenceCalibrator,
)
from .feature_vector import FEATURE_VERSION, MLFeatureVector, build_feature_vector
from .fusion import FusionResult, FusionWeights, WeightedFusionEngine
from .isolation_forest import IsolationForest
from .replay import TemporalSplit, replay_sessions, temporal_split
from .rules import RuleAssessment, RulePolicy
from .severity import Severity, severity_from
from .supervised import SupervisedModelGate
from .temporal import TEMPORAL_WINDOWS, TemporalFeatures, compute_temporal_features
from .versioning import ModelVersionInfo

__all__ = [
    "ConfidenceAssessment",
    "ConfidenceEngine",
    "ConfidenceState",
    "FEATURE_VERSION",
    "FindingConfidenceCalibrator",
    "FusionResult",
    "FusionWeights",
    "IsolationForest",
    "MLFeatureVector",
    "ModelVersionInfo",
    "RuleAssessment",
    "RulePolicy",
    "Severity",
    "SupervisedModelGate",
    "TEMPORAL_WINDOWS",
    "TemporalFeatures",
    "TemporalSplit",
    "WeightedFusionEngine",
    "build_feature_vector",
    "compute_temporal_features",
    "replay_sessions",
    "severity_from",
    "temporal_split",
]
