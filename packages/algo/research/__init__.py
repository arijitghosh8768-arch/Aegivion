"""Aegivion Algorithm #1 - research & evaluation package (Part 4).

Public entry points for the controlled-dataset evaluation harness,
performance benchmarks and artifact generation.
"""

from .datasets import (
    SCENARIO_COMPROMISE,
    SCENARIO_MULTI,
    SCENARIO_NORMAL,
    SCENARIO_SINGLE,
    Scenario,
    build_research_dataset,
)
from .evaluation import (
    SystemEvaluation,
    SystemRunner,
    cross_identity_evaluation,
    drift_stream,
    evaluate_system,
    fp_analysis_records,
    temporal_three_way_split,
    tune_threshold,
)
from .metrics import (
    ConfusionMatrix,
    brier_score,
    expected_calibration_error,
    latency_stats,
    pr_auc,
    precision_at_recall,
    recall_at_fpr,
    roc_auc,
)
from .performance import (
    PerformanceResult,
    run_performance_benchmark,
)
from .reporting import (
    SYNTHETIC_DISCLAIMER,
    render_markdown_report,
    write_research_artifacts,
)

__all__ = [
    "SYNTHETIC_DISCLAIMER",
    "ConfusionMatrix",
    "PerformanceResult",
    "SCENARIO_COMPROMISE",
    "SCENARIO_MULTI",
    "SCENARIO_NORMAL",
    "SCENARIO_SINGLE",
    "Scenario",
    "SystemEvaluation",
    "SystemRunner",
    "brier_score",
    "build_research_dataset",
    "cross_identity_evaluation",
    "drift_stream",
    "expected_calibration_error",
    "evaluate_system",
    "fp_analysis_records",
    "latency_stats",
    "pr_auc",
    "precision_at_recall",
    "recall_at_fpr",
    "render_markdown_report",
    "roc_auc",
    "run_performance_benchmark",
    "temporal_three_way_split",
    "tune_threshold",
    "write_research_artifacts",
]
