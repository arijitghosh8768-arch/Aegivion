"""Error analysis — final stage.

For every **false positive** the spec requires recording: resource
type, activity pattern, top contributing signals, baseline quality,
schedule context, recovery state, model output and ARDE result.

For every **false negative** it requires recording: missing signal,
insufficient telemetry, sequence failure, baseline failure and model
failure.

Both recorders are evidence-driven: every field is read from the
actual detector output (feature vectors, findings, ARDE reports) or
computed directly from the session's telemetry — nothing is invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from detection.cloud_destruction.arde import ValidationReport
from detection.cloud_destruction.config import DestructionDetectorConfig
from detection.cloud_destruction.detector import DetectionOutcome, DestructionDetector
from detection.cloud_destruction.explainability import Explanation
from detection.cloud_destruction.finding import DestructionFinding
from detection.cloud_destruction.schemas import (
    ActionCategory,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

__all__ = [
    "ErrorAnalysisReport",
    "FalseNegativeRecord",
    "FalsePositiveRecord",
    "analyze_errors",
]


def _top_contributions(contributions: dict[str, Optional[float]], limit: int = 5):
    """Top non-null risk contributions, descending."""
    present = [
        (name, value)
        for name, value in (contributions or {}).items()
        if value is not None
    ]
    present.sort(key=lambda item: -item[1])
    return [(name, round(value, 4)) for name, value in present[:limit]]


def _activity_pattern(events: Sequence[ResourceActivityEvent]) -> dict[str, int]:
    """Counts per action category — the session's activity pattern."""
    counts: dict[str, int] = {}
    for event in events:
        key = event.action_category.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _telemetry_summary(events: Sequence[ResourceActivityEvent]) -> dict[str, Any]:
    """Honest telemetry-completeness summary computed from raw events."""
    total = len(events) or 1
    unknown_resources = sum(
        1 for e in events if e.resource_type is None or e.resource_type.value == "unknown"
    )
    missing_actors = sum(1 for e in events if not e.actor_id)
    missing_regions = sum(1 for e in events if not e.region)
    synthetic = sum(
        1 for e in events if e.data_provenance is not None and e.data_provenance.is_synthetic
    )
    return {
        "event_count": len(events),
        "unknown_resource_share": round(unknown_resources / total, 4),
        "missing_actor_share": round(missing_actors / total, 4),
        "missing_region_share": round(missing_regions / total, 4),
        "synthetic_share": round(synthetic / total, 4),
    }


def _recovery_state(vector) -> dict[str, Any]:
    """Recoverability / recovery-destruction state from the feature vector."""
    def _mv(value) -> Optional[float]:
        return value.value if (value is not None and value.available) else None

    return {
        "recoverability": _mv(getattr(vector, "recoverability", None)),
        "recovery_destruction": _mv(
            getattr(vector, "recovery_destruction", None)
        ),
        "protection_degradation": _mv(
            getattr(vector, "protection_degradation", None)
        ),
        "snapshot_deletions": getattr(vector, "ebs_snapshot_deletions", 0)
        + getattr(vector, "rds_snapshot_deletions", 0),
        "backup_anomaly": _mv(getattr(vector, "backup_anomaly", None)),
        "recovery_points_deleted": getattr(
            vector, "unique_recovery_points_deleted", None
        ),
    }


def _arde_result(report: Optional[ValidationReport]) -> dict[str, Any]:
    if report is None:
        return {"ran": False}
    return {
        "ran": True,
        "overall": report.overall.value,
        "challenged": report.challenged,
        "failed_checks": list(report.failed_checks),
        "warnings": list(report.warnings),
    }


def _model_output(
    outcome: DetectionOutcome, session_id: str
) -> dict[str, Any]:
    return {
        "anomaly_score": outcome.anomaly_scores.get(session_id),
        "sequence_score": outcome.sequence_scores.get(session_id),
    }


@dataclass
class FalsePositiveRecord:
    """One false positive with the full spec-mandated context."""

    scenario: str
    session_id: str
    actor_id: Optional[str]
    risk_score: float
    confidence_score: float
    severity: str
    resource_types: tuple[str, ...]
    activity_pattern: dict[str, int]
    top_contributing_signals: list[tuple[str, float]]
    baseline_quality: Optional[str]
    schedule_context: Optional[dict[str, Any]]
    recovery_state: dict[str, Any]
    model_output: dict[str, Any]
    arde_result: dict[str, Any]

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "session_id": self.session_id,
            "actor_id": self.actor_id,
            "risk_score": round(self.risk_score, 4),
            "confidence_score": round(self.confidence_score, 4),
            "severity": self.severity,
            "resource_types": list(self.resource_types),
            "activity_pattern": dict(self.activity_pattern),
            "top_contributing_signals": [
                {"signal": name, "contribution": value}
                for name, value in self.top_contributing_signals
            ],
            "baseline_quality": self.baseline_quality,
            "schedule_context": self.schedule_context,
            "recovery_state": self.recovery_state,
            "model_output": self.model_output,
            "arde_result": self.arde_result,
        }


@dataclass
class FalseNegativeRecord:
    """One false negative with the full spec-mandated diagnostics."""

    scenario: str
    session_id: str
    actor_id: Optional[str]
    risk_score: float
    missing_signal: dict[str, int]
    """Destructive action categories present in the session's telemetry
    (the signal that was present but failed to raise the score)."""
    destructive_event_count: int
    insufficient_telemetry: dict[str, Any]
    sequence_failure: dict[str, Any]
    baseline_failure: dict[str, Any]
    model_failure: dict[str, Any]

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "session_id": self.session_id,
            "actor_id": self.actor_id,
            "risk_score": round(self.risk_score, 4),
            "missing_signal": dict(self.missing_signal),
            "destructive_event_count": self.destructive_event_count,
            "insufficient_telemetry": self.insufficient_telemetry,
            "sequence_failure": self.sequence_failure,
            "baseline_failure": self.baseline_failure,
            "model_failure": self.model_failure,
        }


@dataclass
class ErrorAnalysisReport:
    """Complete error analysis at one decision threshold."""

    threshold: float
    n_sessions: int
    n_false_positives: int
    n_false_negatives: int
    false_positives: tuple[FalsePositiveRecord, ...]
    false_negatives: tuple[FalseNegativeRecord, ...]
    summary: dict[str, Any] = field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "n_sessions": self.n_sessions,
            "n_false_positives": self.n_false_positives,
            "n_false_negatives": self.n_false_negatives,
            "false_positives": [r.to_log_dict() for r in self.false_positives],
            "false_negatives": [r.to_log_dict() for r in self.false_negatives],
            "summary": dict(self.summary),
        }


def analyze_errors(
    events: Sequence[ResourceActivityEvent],
    scenario_labels: dict[str, str],
    *,
    positive_scenarios: Sequence[str],
    threshold: float = 0.35,
    config: Optional[DestructionDetectorConfig] = None,
    anomaly_seed: int = 1337,
) -> ErrorAnalysisReport:
    """Classify every session at ``threshold`` and record FP/FN diagnostics.

    A session is *positive* when any of its events belongs to a
    positive scenario; it is *predicted positive* when its finding
    scores at/above ``threshold``. False positives and false negatives
    are then recorded with the full spec-mandated context.
    """
    config = config or DestructionDetectorConfig()
    positive = frozenset(positive_scenarios)
    detector = DestructionDetector(config, anomaly_seed=anomaly_seed)
    outcome = detector.detect(list(events))

    events_by_id = {e.event_id: e for e in events}
    findings_by_session = {f.session_id: f for f in outcome.findings}
    vectors_by_session = {v.session_id: v for v in outcome.feature_vectors}
    reports_by_session = {r.session_id: r for r in outcome.validation_reports}
    explanations_by_session = {e.session_id: e for e in outcome.explanations}

    session_events: dict[str, list[ResourceActivityEvent]] = {}
    for session in outcome.sessions:
        session_events[session.session_id] = [
            events_by_id[eid] for eid in session.event_ids if eid in events_by_id
        ]

    false_positives: list[FalsePositiveRecord] = []
    false_negatives: list[FalseNegativeRecord] = []

    for session in outcome.sessions:
        session_scenarios = {
            scenario_labels[eid] for eid in session.event_ids if eid in scenario_labels
        }
        is_positive = bool(session_scenarios & positive)
        scenario_name = sorted(session_scenarios)[0] if session_scenarios else "unlabeled"
        finding = findings_by_session.get(session.session_id)
        predicted = finding is not None and finding.risk_score >= threshold
        session_ev = session_events.get(session.session_id, [])
        vector = vectors_by_session.get(session.session_id)
        report = reports_by_session.get(session.session_id)
        explanation = explanations_by_session.get(session.session_id)

        if predicted and not is_positive:
            # ---- false positive: full spec-mandated context ----
            schedule_context = None
            if finding is not None and finding.approved_activity:
                schedule_context = dict(finding.approved_activity)
            if explanation is not None and explanation.what_was_normal:
                schedule_context = schedule_context or {}
                schedule_context["what_was_normal"] = explanation.what_was_normal
            false_positives.append(
                FalsePositiveRecord(
                    scenario=scenario_name,
                    session_id=session.session_id,
                    actor_id=session.actor_id,
                    risk_score=finding.risk_score if finding else 0.0,
                    confidence_score=finding.confidence_score if finding else 0.0,
                    severity=finding.severity.value if finding else "none",
                    resource_types=tuple(
                        sorted(
                            {
                                e.resource_type.value
                                for e in session_ev
                                if e.resource_type is not None
                            }
                        )
                    ),
                    activity_pattern=_activity_pattern(session_ev),
                    top_contributing_signals=(
                        _top_contributions(finding.risk_contributions)
                        if finding
                        else []
                    ),
                    baseline_quality=(
                        vector.baseline_quality.value if vector is not None else None
                    ),
                    schedule_context=schedule_context,
                    recovery_state=_recovery_state(vector) if vector is not None else {},
                    model_output=_model_output(outcome, session.session_id),
                    arde_result=_arde_result(report),
                )
            )
        elif not predicted and is_positive:
            # ---- false negative: spec-mandated diagnostics ----
            missing_signal = _activity_pattern(
                [e for e in session_ev if e.is_destructive]
            )
            baseline_failure = {
                "baseline_quality": (
                    vector.baseline_quality.value if vector is not None else None
                ),
                "baseline_available": (
                    vector is not None
                    and vector.baseline_quality is not None
                    and vector.baseline_quality.value not in ("none",)
                ),
            }
            sequence_score = outcome.sequence_scores.get(session.session_id)
            sequence_failure = {
                "sequence_score": sequence_score,
                "sequence_model_ran": sequence_score is not None,
            }
            anomaly_score = outcome.anomaly_scores.get(session.session_id)
            model_failure = {
                "anomaly_score": anomaly_score,
                "ml_model_ran": anomaly_score is not None,
            }
            false_negatives.append(
                FalseNegativeRecord(
                    scenario=scenario_name,
                    session_id=session.session_id,
                    actor_id=session.actor_id,
                    risk_score=finding.risk_score if finding else 0.0,
                    missing_signal=missing_signal,
                    destructive_event_count=session.destructive_event_count,
                    insufficient_telemetry=_telemetry_summary(session_ev),
                    sequence_failure=sequence_failure,
                    baseline_failure=baseline_failure,
                    model_failure=model_failure,
                )
            )

    n_sessions = len(outcome.sessions)
    summary = {
        "false_positive_rate": round(
            len(false_positives) / max(1, n_sessions), 4
        ),
        "false_negative_rate": round(
            len(false_negatives) / max(1, n_sessions), 4
        ),
        "fp_scenarios": sorted({r.scenario for r in false_positives}),
        "fn_scenarios": sorted({r.scenario for r in false_negatives}),
    }
    return ErrorAnalysisReport(
        threshold=threshold,
        n_sessions=n_sessions,
        n_false_positives=len(false_positives),
        n_false_negatives=len(false_negatives),
        false_positives=tuple(false_positives),
        false_negatives=tuple(false_negatives),
        summary=summary,
    )
