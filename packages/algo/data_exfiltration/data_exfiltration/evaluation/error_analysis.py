"""Error analysis: structured records for every FP and FN.

For every false positive the record captures: reason, top features,
baseline condition, destination type, sensitivity, model output, ARDE
result. For every false negative: which signal was missing, why the
model failed, and what feature could help. These records are the input
for threshold reviews and detector iteration — and an honesty device:
errors are named, not buried.
"""

from __future__ import annotations

from typing import Any, Sequence

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession

from .dataset import LabeledRecord


class FalsePositiveRecord(BaseModel):
    session_id: str
    scenario: str
    reason: str
    top_features: list[str] = Field(default_factory=list)
    baseline_condition: str
    destination_type: str
    sensitivity: float | None
    risk_score: float
    confidence: float | None
    severity: str | None
    arde_result: str | None = None
    robustness_score: float | None = None


class FalseNegativeRecord(BaseModel):
    session_id: str
    scenario: str
    missing_signal: str
    why_model_failed: str
    potential_new_feature: str
    risk_score: float
    confidence: float | None
    arde_result: str | None = None


class ErrorAnalysisReport(BaseModel):
    false_positives: list[FalsePositiveRecord] = Field(default_factory=list)
    false_negatives: list[FalseNegativeRecord] = Field(default_factory=list)
    fp_by_scenario: dict[str, int] = Field(default_factory=dict)
    fn_by_scenario: dict[str, int] = Field(default_factory=dict)

    def as_summary(self) -> dict[str, Any]:
        return {
            "false_positive_count": len(self.false_positives),
            "false_negative_count": len(self.false_negatives),
            "fp_by_scenario": dict(sorted(self.fp_by_scenario.items(), key=lambda kv: -kv[1])),
            "fn_by_scenario": dict(sorted(self.fn_by_scenario.items(), key=lambda kv: -kv[1])),
        }


_QUIET = 0.2
"""Below this a behavioral dimension counts as quiet."""


def _top_features(fset: BehavioralFeatureSet | None) -> list[str]:
    if fset is None:
        return []
    ranked = []
    for name in (
        "volume_score", "object_count_score", "request_rate_score",
        "destination_score", "access_pattern_score", "sensitivity_score",
        "time_score", "actor_resource_score", "egress_score",
    ):
        feature = getattr(fset, name)
        if feature is not None and feature.value is not None:
            ranked.append((name, feature.value))
    ranked.sort(key=lambda kv: -kv[1])
    return [f"{n}={v:.2f}" for n, v in ranked[:4]]


def _baseline_condition(fset: BehavioralFeatureSet | None) -> str:
    if fset is None:
        return "unavailable"
    return (
        f"scope={fset.baseline_scope_used} quality={fset.baseline_quality:.2f} "
        f"cold_start={fset.cold_start}"
    )


def _destination_type(fset: BehavioralFeatureSet | None) -> str:
    if fset is None or fset.destination_score is None:
        return "unavailable"
    detail = fset.destination_score.detail or {}
    worst = detail.get("worst_class")
    return str(worst) if worst else "unclassified"


def _missing_signal(fset: BehavioralFeatureSet | None) -> str:
    """The loudest absent/quiet signal that would have caught this FN."""
    if fset is None:
        return "all features unavailable"
    quiet: list[tuple[str, float]] = []
    for name in (
        "volume_score", "object_count_score", "request_rate_score",
        "destination_score", "access_pattern_score", "sensitivity_score",
        "time_score", "actor_resource_score", "egress_score",
    ):
        feature = getattr(fset, name)
        if feature is None or feature.value is None:
            quiet.append((name, -1.0))
        elif feature.value < _QUIET:
            quiet.append((name, feature.value))
    if not quiet:
        return "no single quiet signal; score distribution too flat"
    quiet.sort(key=lambda kv: kv[1])
    return f"{quiet[0][0]} (value={quiet[0][1]:.2f})"


def _potential_feature(scenario: str) -> str:
    """Per-scenario feature suggestions (documented hypotheses, not promises)."""
    return {
        "slow_exfiltration": (
            "cumulative 24h/7d egress per destination across sessions "
            "(cross-session aggregation; current features are per-session)"
        ),
        "missing_telemetry": (
            "negative-space feature: sensitive-bucket reads with missing "
            "UA/IP are themselves a signal when the actor's history is rich"
        ),
        "unusual_sequence": (
            "ordered action n-grams weighted by destination novelty"
        ),
    }.get(scenario, "none identified in this run; needs manual review")


def analyze_errors(
    records: Sequence[LabeledRecord],
    scored_by_session: dict[str, ScoredSession],
    *,
    threshold: float = 0.5,
    arde_by_session: dict[str, str] | None = None,
    robustness_by_session: dict[str, float] | None = None,
) -> ErrorAnalysisReport:
    """Build the FP/FN report for one variant on one test period."""
    arde = arde_by_session or {}
    robustness = robustness_by_session or {}
    report = ErrorAnalysisReport()

    for record in records:
        scored = scored_by_session.get(record.session_id)
        if scored is None:
            continue
        fset = record.session.session_features.get("_behavioral_feature_set")
        predicted = scored.risk_score >= threshold

        if predicted == 1 and record.label == 0:
            fp = FalsePositiveRecord(
                session_id=record.session_id,
                scenario=record.scenario,
                reason=_fp_reason(record, fset, scored, arde.get(record.session_id)),
                top_features=_top_features(fset),
                baseline_condition=_baseline_condition(fset),
                destination_type=_destination_type(fset),
                sensitivity=(
                    fset.sensitivity_score.value
                    if fset is not None and fset.sensitivity_score else None
                ),
                risk_score=scored.risk_score,
                confidence=scored.confidence_score,
                severity=scored.severity,
                arde_result=arde.get(record.session_id),
                robustness_score=robustness.get(record.session_id),
            )
            report.false_positives.append(fp)
            report.fp_by_scenario[record.scenario] = (
                report.fp_by_scenario.get(record.scenario, 0) + 1
            )
        elif predicted == 0 and record.label == 1:
            fn = FalseNegativeRecord(
                session_id=record.session_id,
                scenario=record.scenario,
                missing_signal=_missing_signal(fset),
                why_model_failed=(
                    f"fused risk {scored.risk_score:.2f} below threshold {threshold:.2f}"
                ),
                potential_new_feature=_potential_feature(record.scenario),
                risk_score=scored.risk_score,
                confidence=scored.confidence_score,
                arde_result=arde.get(record.session_id),
            )
            report.false_negatives.append(fn)
            report.fn_by_scenario[record.scenario] = (
                report.fn_by_scenario.get(record.scenario, 0) + 1
            )
    return report


def _fp_reason(
    record: LabeledRecord,
    fset: BehavioralFeatureSet | None,
    scored: ScoredSession,
    arde: str | None,
) -> str:
    parts: list[str] = []
    if record.scenario in ("normal_backup", "scheduled_etl", "legitimate_migration"):
        parts.append("high-volume routine pattern (volume elevated, corroboration quiet)")
    elif record.scenario == "large_public_transfer":
        parts.append("large volume with zero sensitivity evidence")
    elif record.scenario == "travel_access":
        parts.append("novel source location without behavioral deviation")
    else:
        parts.append("elevated risk on the available evidence")
    if fset is not None and fset.cold_start:
        parts.append("cold-start baseline")
    if arde is not None:
        parts.append(f"arde={arde}")
    return "; ".join(parts)
