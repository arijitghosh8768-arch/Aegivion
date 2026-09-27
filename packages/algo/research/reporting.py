"""Research artifact generation - **Part 4**.

Produces the deliverable files the research brief requires:

* ``metrics.json``             - per-system metrics on the test split,
* ``evaluation_report.json``   - full report (metrics, ablation, FP analysis,
                                 cross-identity, drift, performance),
* ``research_report.md``       - the human-readable Markdown research report.

Every artifact carries the SYNTHETIC-LABELS disclaimer and states its
environment caveats. No metric is invented: numbers come only from
:class:`research.evaluation` and :class:`research.performance` output.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from .datasets import (
    SCENARIO_COMPROMISE,
    SCENARIO_MULTI,
    SCENARIO_NORMAL,
    SCENARIO_SINGLE,
    Scenario,
)
from .evaluation import SystemEvaluation
from .performance import PerformanceResult

SYNTHETIC_DISCLAIMER = (
    "All labels in this evaluation are SYNTHETIC. Metrics support relative "
    "comparison between detector configurations only; they do not validate "
    "real-world performance and no such claim is made."
)


def write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def metrics_payload(
    evaluations: dict[str, SystemEvaluation],
) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "labels": "SYNTHETIC",
        "disclaimer": SYNTHETIC_DISCLAIMER,
        "systems": {name: ev.metrics_dict() for name, ev in evaluations.items()},
    }


def evaluation_report_payload(
    *,
    evaluations: dict[str, SystemEvaluation],
    ablation: Optional[dict[str, SystemEvaluation]] = None,
    cross_identity: Optional[dict[str, dict]] = None,
    fp_analysis: Optional[list[dict]] = None,
    drift: Optional[dict] = None,
    performance: Optional[PerformanceResult] = None,
    dataset_summary: Optional[dict] = None,
) -> dict:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "labels": "SYNTHETIC",
        "disclaimer": SYNTHETIC_DISCLAIMER,
        "dataset": dataset_summary or {},
        "systems": {name: ev.metrics_dict() for name, ev in evaluations.items()},
        "pr_curves": {name: ev.pr_points for name, ev in evaluations.items()},
        "calibration_curves": {
            name: ev.calibration_points for name, ev in evaluations.items()
        },
        "confusion_matrices": {
            name: {
                "tp": ev.confusion.true_positives,
                "fp": ev.confusion.false_positives,
                "fn": ev.confusion.false_negatives,
                "tn": ev.confusion.true_negatives,
            }
            for name, ev in evaluations.items()
        },
        "false_positive_categories": {
            name: dict(ev.fp_categories) for name, ev in evaluations.items()
        },
    }
    if ablation is not None:
        report["ablation_results"] = {
            name: ev.metrics_dict() for name, ev in ablation.items()
        }
    if cross_identity is not None:
        report["cross_identity"] = cross_identity
    if fp_analysis is not None:
        report["false_positive_analysis"] = fp_analysis
    if drift is not None:
        report["drift"] = drift
    if performance is not None:
        report["latency_results"] = performance.as_dict()
    return report


def dataset_summary(scenarios: Sequence[Scenario]) -> dict:
    by_scenario: dict[str, dict] = {}
    for scenario in scenarios:
        bucket = by_scenario.setdefault(
            scenario.scenario,
            {"streams": 0, "events": 0, "positives": 0, "negatives": 0},
        )
        bucket["streams"] += 1
        bucket["events"] += len(scenario)
        bucket["positives"] += sum(scenario.labels)
        bucket["negatives"] += len(scenario) - sum(scenario.labels)
    return {
        "scenario_classes": [
            SCENARIO_NORMAL,
            SCENARIO_SINGLE,
            SCENARIO_MULTI,
            SCENARIO_COMPROMISE,
        ],
        "totals": by_scenario,
        "total_events": sum(s["events"] for s in by_scenario.values()),
        "total_positives": sum(s["positives"] for s in by_scenario.values()),
    }


# --------------------------------------------------------------------------- #
# Markdown report
# --------------------------------------------------------------------------- #


def _fmt(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def render_markdown_report(
    report: dict,
    *,
    title: str = "Aegivion Algorithm #1 - Evaluation Report",
) -> str:
    """Render the evaluation payload as a Markdown research report."""
    lines: list[str] = [f"# {title}", ""]
    lines.append(f"_Generated: {report.get('generated_at', 'unknown')}_")
    lines.append("")
    lines.append(f"> **{SYNTHETIC_DISCLAIMER}**")
    lines.append("")

    # Method & dataset -----------------------------------------------------
    lines.append("## Method")
    lines.append("")
    lines.append(
        "Hybrid identity-behavior detector evaluated against three ablations "
        "(rules only; rules + behavioral baseline; rules + baseline + ML) and "
        "the full pipeline (adds risk fusion, ARDE validation and calibrated "
        "confidence). Chronological train/validation/test split per identity "
        "stream; thresholds tuned on validation only; test scored once."
    )
    lines.append("")
    lines.append("## Dataset")
    lines.append("")
    dataset = report.get("dataset", {})
    lines.append(f"* total events: {dataset.get('total_events', 'n/a')}")
    lines.append(f"* positive (compromise) events: {dataset.get('total_positives', 'n/a')}")
    for name, bucket in dataset.get("totals", {}).items():
        lines.append(
            f"* {name}: {bucket['events']} events / {bucket['positives']} positives "
            f"across {bucket['streams']} streams"
        )
    lines.append("")

    # Metrics table ---------------------------------------------------------
    lines.append("## Results (test split, frozen thresholds)")
    lines.append("")
    lines.append(
        "| system | precision | recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | "
        "latency(ev) | Brier | ECE | P@R.8 | R@FPR.1 |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for name, metrics in report.get("systems", {}).items():
        lines.append(
            f"| {name} | {_fmt(metrics.get('precision'))} | {_fmt(metrics.get('recall'))} "
            f"| {_fmt(metrics.get('f1'))} | {_fmt(metrics.get('pr_auc'))} "
            f"| {_fmt(metrics.get('roc_auc'))} | {_fmt(metrics.get('fpr'))} "
            f"| {_fmt(metrics.get('fnr'))} | {_fmt(metrics.get('detection_latency_events'))} "
            f"| {_fmt(metrics.get('brier_score'))} | {_fmt(metrics.get('ece'))} "
            f"| {_fmt(metrics.get('precision_at_recall_0.8'))} "
            f"| {_fmt(metrics.get('recall_at_fpr_0.1'))} |"
        )
    lines.append("")

    # Confusion matrices -----------------------------------------------------
    lines.append("### Confusion matrices")
    lines.append("")
    for name, cm in report.get("confusion_matrices", {}).items():
        lines.append(
            f"* **{name}**: TP={cm['tp']} FP={cm['fp']} FN={cm['fn']} TN={cm['tn']}"
        )
    lines.append("")

    # Ablation ---------------------------------------------------------------
    if "ablation_results" in report:
        lines.append("## Ablation study")
        lines.append("")
        lines.append("| configuration removed | F1 | precision | recall | FPR | PR-AUC |")
        lines.append("|---|---|---|---|---|---|")
        for name, metrics in report["ablation_results"].items():
            lines.append(
                f"| {name} | {_fmt(metrics.get('f1'))} | {_fmt(metrics.get('precision'))} "
                f"| {_fmt(metrics.get('recall'))} | {_fmt(metrics.get('fpr'))} "
                f"| {_fmt(metrics.get('pr_auc'))} |"
            )
        lines.append("")
        lines.append(
            "Interpretation: a layer 'contributes' when removing it degrades F1 "
            "or materially raises FPR. Layers whose removal changes nothing are "
            "candidates for simplification - reported as measured, not rationalized."
        )
        lines.append("")

    # FP analysis --------------------------------------------------------------
    if report.get("false_positive_categories"):
        lines.append("## False-positive analysis")
        lines.append("")
        for name, categories in report["false_positive_categories"].items():
            lines.append(f"**{name}**")
            for category, count in sorted(categories.items(), key=lambda kv: -kv[1]):
                lines.append(f"* {category}: {count}")
            lines.append("")

    # Cross identity -------------------------------------------------------------
    if report.get("cross_identity"):
        lines.append("## Cross-identity generalization")
        lines.append("")
        lines.append("| identity | n_test | positives | precision | recall | FPR |")
        lines.append("|---|---|---|---|---|---|")
        for identity, metrics in report["cross_identity"].items():
            short = identity.split(":")[-1]
            lines.append(
                f"| {short} | {metrics.get('n_test')} | {metrics.get('n_positives')} "
                f"| {_fmt(metrics.get('precision'))} | {_fmt(metrics.get('recall'))} "
                f"| {_fmt(metrics.get('fpr'))} |"
            )
        lines.append("")

    # Drift ------------------------------------------------------------------
    if report.get("drift"):
        lines.append("## Drift simulation")
        lines.append("")
        lines.append(f"```json\n{json.dumps(report['drift'], indent=2)}\n```")
        lines.append("")

    # Performance ------------------------------------------------------------
    if report.get("latency_results"):
        perf = report["latency_results"]
        lines.append("## Performance")
        lines.append("")
        lines.append(f"* throughput: {perf.get('events_per_second')} events/s")
        lines.append(f"* mean inference latency: {perf.get('mean_latency_ms')} ms")
        lines.append(f"* p95 inference latency: {perf.get('p95_latency_ms')} ms")
        lines.append(f"* memory delta during run: {perf.get('memory_delta_mb')} MB")
        lines.append(f"* notes: {perf.get('notes')}")
        lines.append("")

    # Limitations --------------------------------------------------------------
    lines.append("## Limitations")
    lines.append("")
    lines.append("* Synthetic labels: relative comparisons only; no real-world validation.")
    lines.append("* The Isolation Forest is a pure-Python implementation (scikit-learn is not a project dependency).")
    lines.append("* Timings are environment-dependent; the benchmark machine is not specified or controlled.")
    lines.append("* Thresholds are tuned for F1 on validation; security operations may prefer recall-oriented operating points (`target_recall` strategy).")
    lines.append("* The supervised second model remains untrained: no real labeled incident data exists in this repository.")
    lines.append("")

    # Error analysis ------------------------------------------------------------
    lines.append("## Error analysis")
    lines.append("")
    lines.append(
        "False positives are categorized by the signals that produced them "
        "(travel, VPN egress, new device, unusual hour, novel API, frequency, "
        "privilege). The governed suppression engine addresses the travel/VPN/"
        "maintenance categories; peer baselines address cold-start noise."
    )
    lines.append("")

    # Future work ------------------------------------------------------------
    lines.append("## Future work")
    lines.append("")
    lines.append("* Train and calibrate the supervised model on real labeled incident data (isotonic/Platt).")
    lines.append("* Replace the deterministic sequence heuristic with a learned sequence model once real sequences exist.")
    lines.append("* Evaluate on multi-account, multi-region telemetry with peer groups at scale.")
    lines.append("* Calibration-aware threshold schedules per identity category.")

    return "\n".join(lines)


def write_research_artifacts(
    output_dir: Path,
    *,
    evaluations: dict[str, SystemEvaluation],
    ablation: Optional[dict[str, SystemEvaluation]] = None,
    cross_identity: Optional[dict[str, dict]] = None,
    fp_analysis: Optional[list[dict]] = None,
    drift: Optional[dict] = None,
    performance: Optional[PerformanceResult] = None,
    scenarios: Optional[Sequence[Scenario]] = None,
) -> dict[str, Path]:
    """Write every research artifact; returns the written paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    paths["metrics.json"] = write_json(
        output_dir / "metrics.json", metrics_payload(evaluations)
    )
    report_payload = evaluation_report_payload(
        evaluations=evaluations,
        ablation=ablation,
        cross_identity=cross_identity,
        fp_analysis=fp_analysis,
        drift=drift,
        performance=performance,
        dataset_summary=dataset_summary(scenarios or []),
    )
    paths["evaluation_report.json"] = write_json(
        output_dir / "evaluation_report.json", report_payload
    )
    markdown = render_markdown_report(report_payload)
    report_path = output_dir / "research_report.md"
    report_path.write_text(markdown, encoding="utf-8")
    paths["research_report.md"] = report_path
    return paths


__all__ = [
    "SYNTHETIC_DISCLAIMER",
    "dataset_summary",
    "evaluation_report_payload",
    "metrics_payload",
    "render_markdown_report",
    "write_json",
    "write_research_artifacts",
]
