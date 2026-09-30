"""Final-stage evaluation package (Part 5).

A–E variant comparison over the 15-scenario synthetic corpus, ablation
study, error analysis, and performance measurement. Everything is
deterministic (seed 42) and marked synthetic in every artifact.
"""

from __future__ import annotations

from .ablation import ABLATABLE_COMPONENTS, AblationResult, ablate_features, ablate_stack
from .dataset import LabeledRecord, build_sessions_from_bundle, run_detector_on_corpus
from .error_analysis import (
    ErrorAnalysisReport,
    FalseNegativeRecord,
    FalsePositiveRecord,
    analyze_errors,
)
from .metrics import (
    detection_latency_ms,
    detection_lead_time_s,
    false_negative_rate,
    full_metrics,
    precision_at_high_risk,
    recall_at_fixed_fpr,
)
from .performance import PerformanceReport, measure_detector_batch, measure_detector_streaming
from .runner import evaluate, prepare_feature_records, write_report
from .tuning import (
    ThresholdSelection,
    run_threshold_tuning,
    split_records,
    threshold_curve,
    tune_threshold,
    verify_split_integrity,
)
from .scenarios import (
    BENIGN_GENERATORS,
    EXFIL_GENERATORS,
    FIFTEEN_FAMILIES,
    SCENARIO_GENERATORS,
    ScenarioBundle,
    build_instances,
)
from .variants import run_variants, score_with_arde

__all__ = [
    "ABLATABLE_COMPONENTS",
    "BENIGN_GENERATORS",
    "EXFIL_GENERATORS",
    "ErrorAnalysisReport",
    "FIFTEEN_FAMILIES",
    "FalseNegativeRecord",
    "FalsePositiveRecord",
    "LabeledRecord",
    "PerformanceReport",
    "SCENARIO_GENERATORS",
    "ScenarioBundle",
    "ThresholdSelection",
    "AblationResult",
    "ablate_features",
    "ablate_stack",
    "analyze_errors",
    "build_instances",
    "build_sessions_from_bundle",
    "detection_latency_ms",
    "detection_lead_time_s",
    "evaluate",
    "false_negative_rate",
    "full_metrics",
    "measure_detector_batch",
    "measure_detector_streaming",
    "precision_at_high_risk",
    "prepare_feature_records",
    "recall_at_fixed_fpr",
    "run_detector_on_corpus",
    "run_threshold_tuning",
    "run_variants",
    "score_with_arde",
    "split_records",
    "threshold_curve",
    "tune_threshold",
    "verify_split_integrity",
    "write_report",
]
