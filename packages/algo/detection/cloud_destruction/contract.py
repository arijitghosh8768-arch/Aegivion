"""Final finding contract + dashboard data — final stage.

Two serializers, both strictly evidence-derived:

- :func:`build_finding_contract` — the **final finding contract**
  mandated by the spec (finding_type … rule_version, plus
  ``recommended_next_steps``). ``robustness_score`` is *derived*
  from the ARDE report (share of checks passing, warnings at
  half credit, failures at zero) — never fabricated.
- :func:`build_dashboard_data` — the **dashboard payload**
  (Potential Cloud Destructive Activity, Risk Score, Confidence,
  Robustness Score, Resources Affected, Modification Rate,
  Deletion Rate, Version Deletion, Snapshot Deletion, Backup
  Deletion, Recovery Status, Protection Changes, Timeline,
  Normal vs Observed, Top Signals, Contradicting Evidence,
  Recommended Next Steps).

The preferred finding wording — **"Potential Cloud Destructive
Activity"** — is used as ``finding_type`` throughout; the contract
never claims confirmed ransomware or perfect detection.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from detection.cloud_destruction.arde import CheckVerdict, ValidationReport
from detection.cloud_destruction.explainability import Explanation
from detection.cloud_destruction.finding import DestructionFinding
from detection.cloud_destruction.schemas import (
    ActionCategory,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

__all__ = [
    "build_dashboard_data",
    "build_finding_contract",
    "robustness_score",
]

FINDING_TYPE = "Potential Cloud Destructive Activity"

#: Next-step playbooks keyed by destructive behavior category.
#: Wording is advisory and evidence-derived (the category was
#: observed in the session), never a claim of confirmed intent.
_CATEGORY_NEXT_STEPS: dict[str, str] = {
    "MASS_MODIFICATION": (
        "Sample modified objects for unauthorized changes and compare "
        "against the last known-good state."
    ),
    "MASS_DELETION": (
        "Review deletion audit logs for the acting identity and isolate "
        "affected resources."
    ),
    "VERSION_DESTRUCTION": (
        "Verify object-version integrity and assess restoration from any "
        "remaining protected versions."
    ),
    "RECOVERY_DESTRUCTION": (
        "Validate backup and snapshot integrity immediately and "
        "re-establish recovery points."
    ),
    "PROTECTION_DEGRADATION": (
        "Review protection-state changes and re-enable disabled "
        "versioning/backup controls."
    ),
    "MASS_REWRITE": (
        "Audit rewrite chains for data tampering against known-good copies."
    ),
    "MULTI_RESOURCE_DESTRUCTION": (
        "Scope the blast radius across affected resources and accounts."
    ),
    "COMPOUND_DESTRUCTIVE_ACTIVITY": (
        "Escalate as a coordinated incident: multiple destructive patterns "
        "co-occur in one session."
    ),
}

_RECOVERY_STATUS: tuple[tuple[float, str], ...] = (
    (0.8, "intact"),
    (0.5, "degraded"),
    (0.0, "destroyed"),
)


def robustness_score(report: Optional[ValidationReport]) -> float:
    """Derive robustness from the ARDE report.

    Share of checks passing; WARN counts at half credit, FAIL at
    zero. No report → 0.0 (robustness unknown is reported as the
    worst case, never as a fabricated pass).
    """
    if report is None or not report.checks:
        return 0.0
    total = len(report.checks)
    credit = 0.0
    for check in report.checks.values():
        if check.verdict is CheckVerdict.PASS:
            credit += 1.0
        elif check.verdict is CheckVerdict.WARN:
            credit += 0.5
    return round(max(0.0, min(1.0, credit / total)), 4)


def _recoverability_display(value: Optional[float]) -> str:
    if value is None:
        return "unknown"
    for floor, label in _RECOVERY_STATUS:
        if value >= floor:
            return label
    return "destroyed"


def _recommended_next_steps(
    finding: DestructionFinding,
    explanation: Optional[Explanation],
    telemetry_completeness: Optional[str],
) -> list[str]:
    steps: list[str] = []
    categories = set(explanation.categories) if explanation else set()
    for category in sorted(categories):
        step = _CATEGORY_NEXT_STEPS.get(category)
        if step and step not in steps:
            steps.append(step)
    if finding.severity.value in ("high", "critical"):
        steps.append(
            "Escalate to the incident-response on-call with the full "
            "evidence bundle (session events, ARDE report, feature vector)."
        )
    if finding.confidence_score < 0.5:
        steps.append(
            "Confidence is moderate — collect additional telemetry before "
            "disruptive response actions."
        )
    if telemetry_completeness == "LOW":
        steps.append(
            "Telemetry completeness is LOW — verify ingestion coverage for "
            "the affected resources before relying on absence of evidence."
        )
    if not steps:
        steps.append(
            "No destructive behavior category was recognized; continue "
            "routine monitoring."
        )
    return steps


def build_finding_contract(
    finding: DestructionFinding,
    session: DestructiveActivitySession,
    *,
    explanation: Optional[Explanation] = None,
    report: Optional[ValidationReport] = None,
    vector=None,
    events: Sequence[ResourceActivityEvent] = (),
) -> dict[str, Any]:
    """Serialize one finding into the final finding contract."""
    contributions = [
        {"signal": name, "contribution": value}
        for name, value in sorted(
            (
                (k, v)
                for k, v in (finding.risk_contributions or {}).items()
                if v is not None
            ),
            key=lambda item: -item[1],
        )[:5]
    ]
    telemetry_completeness = (
        explanation.telemetry_completeness if explanation else None
    )
    recoverability_value = None
    if vector is not None and getattr(vector, "recoverability", None) is not None:
        rv = vector.recoverability
        if getattr(rv, "available", False):
            recoverability_value = rv.value
    business_criticality = None
    if vector is not None and getattr(vector, "business_criticality", None) is not None:
        business_criticality = vector.business_criticality.value

    return {
        "finding_type": FINDING_TYPE,
        "severity": finding.severity.value,
        "risk_score": round(finding.risk_score, 4),
        "confidence": round(finding.confidence_score, 4),
        "robustness_score": robustness_score(report),
        "actor": finding.actor_id,
        "session": finding.session_id,
        "resources_affected": {
            "count": len(session.resources_touched),
            "resource_ids": list(session.resources_touched),
        },
        "modifications": len(session.modified_resources),
        "deletions": len(session.deleted_resources),
        "version_deletions": session.version_deletions,
        "snapshot_deletions": session.snapshot_deletions,
        "backup_deletions": session.backup_deletions,
        "protection_changes": session.protection_changes,
        "business_criticality": business_criticality or "unclassified",
        "recoverability": {
            "score": recoverability_value,
            "status": _recoverability_display(recoverability_value),
        },
        "signals": contributions,
        "supporting_evidence": (
            list(explanation.supporting_evidence) if explanation else []
        ),
        "contradicting_evidence": (
            list(explanation.contradicting_evidence) if explanation else []
        ),
        "baseline_quality": (
            explanation.baseline_quality if explanation else None
        ),
        "telemetry_completeness": telemetry_completeness,
        "model_version": finding.model_version,
        "feature_version": finding.feature_version,
        "baseline_version": finding.baseline_version,
        "scoring_version": finding.scoring_version,
        "rule_version": finding.rule_version,
        "recommended_next_steps": _recommended_next_steps(
            finding, explanation, telemetry_completeness
        ),
    }


def _rates(
    session: DestructiveActivitySession, events: Sequence[ResourceActivityEvent]
) -> tuple[Optional[float], Optional[float]]:
    """Modification + deletion rates per hour (honest arithmetic)."""
    hours = (session.duration_seconds or 0.0) / 3600.0
    if hours <= 0.0 or not events:
        return None, None
    modifies = sum(1 for e in events if e.action_category is ActionCategory.MODIFY)
    deletes = sum(1 for e in events if e.action_category is ActionCategory.DELETE)
    return round(modifies / hours, 4), round(deletes / hours, 4)


def _normal_vs_observed(vector) -> list[dict[str, Any]]:
    """Baseline ('normal') vs observed for the key behavioral features."""
    if vector is None:
        return []
    rows: list[dict[str, Any]] = []
    for name in (
        "modify_rate_deviation",
        "delete_rate_deviation",
        "delete_ratio_anomaly",
        "resource_scope_deviation",
        "rewrite_rate_deviation",
    ):
        measured = getattr(vector, name, None)
        if measured is None:
            continue
        row: dict[str, Any] = {
            "feature": name,
            "observed": measured.value,
            "available": measured.available,
        }
        if measured.available and measured.raw:
            row["normal_baseline"] = dict(measured.raw)
        rows.append(row)
    return rows


def _timeline(events: Sequence[ResourceActivityEvent]) -> list[dict[str, Any]]:
    ordered = sorted(events, key=lambda e: e.timestamp)
    return [
        {
            "timestamp": e.timestamp.isoformat(),
            "action_category": e.action_category.value,
            "actor_id": e.actor_id,
            "resource_id": e.resource_id,
        }
        for e in ordered
    ]


def build_dashboard_data(
    contract: dict[str, Any],
    *,
    session: Optional[DestructiveActivitySession] = None,
    explanation: Optional[Explanation] = None,
    vector=None,
    events: Sequence[ResourceActivityEvent] = (),
) -> dict[str, Any]:
    """Build the dashboard payload from a finding contract + evidence."""
    modification_rate, deletion_rate = (
        _rates(session, events) if session is not None else (None, None)
    )
    recoverability_score = contract.get("recoverability", {}).get("score")
    return {
        "potential_cloud_destructive_activity": contract.get("finding_type"),
        "risk_score": contract.get("risk_score"),
        "confidence": contract.get("confidence"),
        "robustness_score": contract.get("robustness_score"),
        "resources_affected": contract.get("resources_affected"),
        "modification_rate": modification_rate,
        "deletion_rate": deletion_rate,
        "version_deletion": contract.get("version_deletions"),
        "snapshot_deletion": contract.get("snapshot_deletions"),
        "backup_deletion": contract.get("backup_deletions"),
        "recovery_status": {
            "score": recoverability_score,
            "state": (
                contract.get("recoverability", {}).get("status")
                if contract.get("recoverability")
                else "unknown"
            ),
            "recovery_destruction": (
                vector.recovery_destruction.value
                if vector is not None
                and getattr(vector, "recovery_destruction", None) is not None
                and vector.recovery_destruction.available
                else None
            ),
        },
        "protection_changes": contract.get("protection_changes"),
        "timeline": _timeline(events),
        "normal_vs_observed": _normal_vs_observed(vector),
        "top_signals": contract.get("signals"),
        "contradicting_evidence": contract.get("contradicting_evidence"),
        "recommended_next_steps": contract.get("recommended_next_steps"),
    }
