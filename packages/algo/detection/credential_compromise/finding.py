"""Finding assembly - **Part 2/3**.

Turns a fully scored, ARDE-validated event into the final, explainable,
persistable finding dict (shape-compatible with
``storage.finding_repository.FindingRecord``).

Determinism contract: the same event, model version, baseline version and
configuration always produce the same finding. Timestamps are taken from the
event/session data, never from the wall clock.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from algo.detection.credential_compromise.arde import ArdeResult
from algo.detection.credential_compromise.attack_mapping import map_signals_to_attack
from algo.detection.credential_compromise.explainability import Explanation
from algo.detection.credential_compromise.model_registry import ComponentVersions
from algo.detection.credential_compromise.schemas import (
    IdentityActivityEvent,
    IdentitySession,
    Severity,
    mask_secret,
)


def build_finding(
    *,
    event: IdentityActivityEvent,
    risk: float,
    confidence: float,
    severity: Severity,
    signals: Sequence,
    feature_evidence: dict[str, Any],
    fusion_contributions: dict[str, float],
    versions: ComponentVersions,
    session_key: Optional[str] = None,
    detection_mode: str = "REAL_TIME",
) -> dict[str, Any]:
    """Assemble the detection-layer finding payload (deterministic)."""
    rule_payloads = [
        signal.to_dict() if hasattr(signal, "to_dict") else dict(signal)
        for signal in signals
    ]
    return {
        "finding_id": f"CCD-{event.event_id}",
        "finding_type": "credential_compromise",
        "identity_key": event.identity_key or event.principal_id,
        "provider": event.provider.value,
        "account_id": event.account_id,
        "principal_id": event.principal_id,
        "principal_name": event.principal_name,
        "access_key_masked": mask_secret(event.access_key_id),
        "severity": severity.value,
        "risk_score": risk,
        "confidence": confidence,
        "signals": rule_payloads,
        "evidence": {
            "features": feature_evidence,
            "fusion_contributions": fusion_contributions,
            "detection_mode": detection_mode,
        },
        "session_key": session_key,
        "event_id": event.event_id,
        "first_seen": event.timestamp,
        "last_seen": event.timestamp,
        "model_name": versions.model_name,
        "model_version": versions.model_version,
        "feature_version": versions.feature_version,
        "baseline_version": versions.baseline_version,
        "rule_version": versions.rule_version,
        "scoring_version": versions.scoring_version,
        "status": "OPEN",
    }


def finalize_finding(
    *,
    detection_finding: dict[str, Any],
    event: IdentityActivityEvent,
    session: Optional[IdentitySession],
    arde_result: ArdeResult,
    explanation: Explanation,
    versions: ComponentVersions,
    suppression_note: Optional[str] = None,
) -> dict[str, Any]:
    """Produce the final finding with ARDE validation and full evidence.

    Adds ``robustness_score``, ``validation_status``, ARDE checks, the
    machine-readable explanation, supporting/contradicting features, ATT&CK
    mapping and audited next steps. Deterministic: derived only from the
    supplied inputs.
    """
    finding = dict(detection_finding)
    rule_payloads = finding.get("signals", [])
    rule_ids = [str(signal.get("rule_id")) for signal in rule_payloads]

    # Session identity is data, not wall clock.
    if session is not None:
        finding["session_key"] = session.session_key
        finding["first_seen"] = min(event.timestamp, session.start_time)
        finding["last_seen"] = max(event.timestamp, session.last_seen)

    finding["robustness_score"] = arde_result.robustness_score
    finding["validation_status"] = arde_result.validation_status
    finding["arde"] = arde_result.to_dict()
    finding["explanation"] = explanation.to_dict()
    finding["supporting_features"] = [
        entry.get("feature") or entry.get("label")
        for entry in explanation.supporting_evidence
    ]
    finding["contradicting_features"] = [
        entry.get("feature") or entry.get("label")
        for entry in explanation.contradicting_evidence
    ]
    finding["baseline_quality"] = explanation.baseline_quality
    finding["model_versions"] = {
        "model_name": versions.model_name,
        "model_version": versions.model_version,
        "feature_version": versions.feature_version,
        "scoring_version": versions.scoring_version,
    }
    finding["rule_versions"] = {"rule_version": versions.rule_version}
    finding["ATTACK_mapping"] = map_signals_to_attack(
        rule_ids, api_family=event.api_family
    )
    finding["recommended_next_steps"] = _next_steps(
        severity=Severity(finding["severity"]),
        validation_status=arde_result.validation_status,
        needs_review=arde_result.needs_review,
        rule_ids=rule_ids,
        suppression_note=suppression_note,
    )
    if suppression_note:
        finding["suppression_note"] = suppression_note
    return finding


def _next_steps(
    *,
    severity: Severity,
    validation_status: str,
    needs_review: bool,
    rule_ids: list[str],
    suppression_note: Optional[str],
) -> list[str]:
    """Deterministic response guidance. Detection only - never remediation."""
    steps: list[str] = []
    if validation_status == "REJECTED":
        steps.append("Do not act on this finding: ARDE rejected the evidence quality.")
        steps.append("Investigate the telemetry source for gaps or manipulation.")
        return steps
    if needs_review or validation_status == "REVIEW_REQUIRED":
        steps.append("Assign a human analyst: evidence layers disagree or are incomplete.")
    if validation_status == "PASSED_WITH_WARNINGS":
        steps.append("Review ARDE warnings before escalating.")
    if severity in (Severity.HIGH, Severity.CRITICAL):
        steps.append("Verify recent activity with the identity owner.")
        if "R010" in rule_ids or "R012" in rule_ids:
            steps.append("Stage credential rotation for review by the response layer.")
    if "R001" in rule_ids or "R004" in rule_ids:
        steps.append("Check whether the geography/network is an approved travel or VPN path.")
    if suppression_note:
        steps.append(suppression_note)
    if not steps:
        steps.append("Archive finding with its evidence bundle.")
    return steps


__all__ = ["build_finding", "finalize_finding"]
