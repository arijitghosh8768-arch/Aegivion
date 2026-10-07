"""Leave-one-out ablation study — final stage.

Removes one component at a time from the full Aegivion detector and
measures the impact on scenario-level detection, answering the spec's
question: *which parts actually contribute?*

Ablated components (per the final-stage spec):

- ``without_baseline``        — baseline-relative behavioral features off;
- ``without_sequence``        — sequence transition model off;
- ``without_ml``              — Isolation Forest anomaly off;
- ``without_recovery_analysis`` — snapshot + backup scoring weights zeroed
  (their weight redistributes to the remaining evidence-backed components,
  exactly as the scorer does for any unavailable feature);
- ``without_recoverability``  — recoverability scoring weight zeroed;
- ``without_criticality``     — business-criticality scoring weight zeroed;
- ``without_arde``            — ARDE challenge validator replaced by a
  pass-through no-op.

**Honesty rule**: ARDE never mutates findings (it challenges and
annotates, it never suppresses), so removing it cannot change
detection metrics — the delta is honestly reported as 0 and the
study instead reports ARDE's *challenge statistics* (how many
findings it WARNed/FAILed) so its contribution is visible without
fabricating a detection delta.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from algo.detection.cloud_destruction.arde import (
    CheckVerdict,
    ValidationCheck,
    ValidationReport,
)
from algo.detection.cloud_destruction.config import DestructionDetectorConfig
from algo.detection.cloud_destruction.detector import DestructionDetector
from algo.detection.cloud_destruction.evaluation import _pr_auc, _roc_auc
from algo.detection.cloud_destruction.schemas import (
    DestructiveActivitySession,
    ResourceActivityEvent,
)
from algo.detection.cloud_destruction.scorer import ScoringConfig

__all__ = ["AblationResult", "AblationStudy", "run_ablation"]


class _NoOpArdeValidator:
    """Pass-through ARDE stand-in: every check passes, nothing challenged."""

    def validate(
        self,
        finding,
        session,
        vector,
        risk,
        confidence,
        events: Sequence[ResourceActivityEvent] = (),
    ) -> ValidationReport:
        check_ids = (
            "event_consistency",
            "sequence_consistency",
            "resource_consistency",
            "time_consistency",
            "baseline_consistency",
            "recovery_consistency",
            "model_rule_agreement",
            "telemetry_completeness",
            "protection_state_consistency",
            "feature_provenance_validation",
        )
        checks = {
            check_id: ValidationCheck(
                check_id=check_id,
                verdict=CheckVerdict.PASS,
                reasons=("ablated: ARDE validator disabled",),
            )
            for check_id in check_ids
        }
        return ValidationReport(
            finding_id=finding.finding_id,
            session_id=session.session_id,
            overall=CheckVerdict.PASS,
            checks=checks,
        )


@dataclass
class AblationResult:
    """One leave-one-out run (or the full-detector baseline)."""

    name: str
    description: str
    n_sessions: int
    n_scenarios: int
    threshold: float
    precision: float
    recall: float
    f1: float
    pr_auc: float
    roc_auc: float
    false_positive_rate: float
    detected_scenarios: tuple[str, ...]
    scenario_scores: dict[str, float]
    challenge_stats: dict[str, int] = field(default_factory=dict)
    delta_vs_full: dict[str, float] = field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "n_sessions": self.n_sessions,
            "n_scenarios": self.n_scenarios,
            "threshold": self.threshold,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "pr_auc": round(self.pr_auc, 4),
            "roc_auc": round(self.roc_auc, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "detected_scenarios": list(self.detected_scenarios),
            "scenario_scores": {
                k: round(v, 4) for k, v in self.scenario_scores.items()
            },
            "challenge_stats": dict(self.challenge_stats),
            "delta_vs_full": {k: round(v, 4) for k, v in self.delta_vs_full.items()},
        }


@dataclass
class AblationStudy:
    """Complete leave-one-out study with the full detector as baseline."""

    baseline: AblationResult
    results: tuple[AblationResult, ...]
    threshold: float

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "baseline": self.baseline.to_log_dict(),
            "ablations": [r.to_log_dict() for r in self.results],
        }


def _scenario_metrics(
    outcome,
    scenario_labels: dict[str, str],
    positive_scenarios: frozenset[str],
    threshold: float,
) -> dict[str, Any]:
    """Scenario-level metrics: a scenario fires iff any of its sessions fires."""
    best: dict[str, float] = {}
    for finding in outcome.findings:
        for event_id in finding.event_ids:
            scenario = scenario_labels.get(event_id)
            if scenario is None:
                continue
            best[scenario] = max(best.get(scenario, 0.0), finding.risk_score)
    # sessions with no finding score 0.0 — they still count as scenario evidence
    for session in outcome.sessions:
        for event_id in session.event_ids:
            scenario = scenario_labels.get(event_id)
            if scenario is not None:
                best.setdefault(scenario, 0.0)
    names = sorted(set(scenario_labels.values()))
    labels = [name in positive_scenarios for name in names]
    scores = [best.get(name, 0.0) for name in names]
    predicted_positive = {
        name for name, score in zip(names, scores) if score >= threshold
    }
    tp = len(predicted_positive & positive_scenarios)
    fp = len(predicted_positive - positive_scenarios)
    fn = len(positive_scenarios - predicted_positive)
    tn = len(
        [n for n in names if n not in positive_scenarios and n not in predicted_positive]
    )
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "pr_auc": _pr_auc(scores, labels),
        "roc_auc": _roc_auc(scores, labels),
        "false_positive_rate": fpr,
        "detected": tuple(sorted(predicted_positive)),
        "scores": {name: best.get(name, 0.0) for name in names},
    }


def _challenge_stats(outcome) -> dict[str, int]:
    """ARDE challenge statistics (used when ARDE itself is ablated)."""
    stats = {"findings": len(outcome.validation_reports), "challenged": 0, "warnings": 0, "failures": 0}
    for report in outcome.validation_reports:
        if report.challenged:
            stats["challenged"] += 1
        stats["warnings"] += len(report.warnings)
        stats["failures"] += len(report.failed_checks)
    return stats


def run_ablation(
    events: Sequence[ResourceActivityEvent],
    scenario_labels: dict[str, str],
    *,
    positive_scenarios: Sequence[str],
    config: Optional[DestructionDetectorConfig] = None,
    threshold: float = 0.35,
    anomaly_seed: int = 1337,
) -> AblationStudy:
    """Run the full detector plus all seven leave-one-out ablations.

    ``scenario_labels`` maps every event id to its scenario name;
    ``positive_scenarios`` lists the scenario names that represent
    destructive activity. Metrics are computed at the scenario level
    (a scenario is detected when any session containing its events
    produces a finding at/above ``threshold``).
    """
    config = config or DestructionDetectorConfig()
    positive = frozenset(positive_scenarios)

    def _run(name: str, description: str, **kwargs: Any) -> AblationResult:
        detector = DestructionDetector(config, anomaly_seed=anomaly_seed, **kwargs)
        outcome = detector.detect(list(events))
        metrics = _scenario_metrics(outcome, scenario_labels, positive, threshold)
        return AblationResult(
            name=name,
            description=description,
            n_sessions=len(outcome.sessions),
            n_scenarios=len(set(scenario_labels.values())),
            threshold=threshold,
            precision=metrics["precision"],
            recall=metrics["recall"],
            f1=metrics["f1"],
            pr_auc=metrics["pr_auc"],
            roc_auc=metrics["roc_auc"],
            false_positive_rate=metrics["false_positive_rate"],
            detected_scenarios=metrics["detected"],
            scenario_scores=dict(metrics["scores"]),
            challenge_stats=_challenge_stats(outcome),
        )

    baseline = _run(
        "full",
        "full Aegivion detector (all components)",
    )

    ablations = (
        (
            "without_baseline",
            "baseline-relative behavioral features disabled (use_baseline=False)",
            {"use_baseline": False},
        ),
        (
            "without_sequence",
            "sequence transition model disabled (use_sequence_model=False)",
            {"use_sequence_model": False},
        ),
        (
            "without_ml",
            "Isolation Forest anomaly scoring disabled (use_ml=False)",
            {"use_ml": False},
        ),
        (
            "without_recovery_analysis",
            "snapshot + backup scoring weights zeroed (recovery analysis off)",
            {"scoring_config": ScoringConfig(weight_snapshot=0.0, weight_backup=0.0)},
        ),
        (
            "without_recoverability",
            "recoverability scoring weight zeroed",
            {"scoring_config": ScoringConfig(weight_recoverability=0.0)},
        ),
        (
            "without_criticality",
            "business-criticality scoring weight zeroed",
            {"scoring_config": ScoringConfig(weight_criticality=0.0)},
        ),
        (
            "without_arde",
            "ARDE challenge validator replaced by a pass-through no-op",
            {"arde_validator": _NoOpArdeValidator()},
        ),
    )

    results: list[AblationResult] = []
    for name, description, kwargs in ablations:
        result = _run(name, description, **kwargs)
        result.delta_vs_full = {
            "precision": result.precision - baseline.precision,
            "recall": result.recall - baseline.recall,
            "f1": result.f1 - baseline.f1,
            "false_positive_rate": result.false_positive_rate
            - baseline.false_positive_rate,
        }
        results.append(result)

    return AblationStudy(baseline=baseline, results=tuple(results), threshold=threshold)
