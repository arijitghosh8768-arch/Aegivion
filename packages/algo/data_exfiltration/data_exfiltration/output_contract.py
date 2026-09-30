"""Stable output contract for every released finding.

Findings already carry rich evidence (ARDE payload, scoring metadata, model
identity). This module defines the *stable, documented* shape downstream
consumers (Threat Correlation, dashboards, APIs) can rely on: one flat block
under ``finding.metadata["output_contract"]`` with a fixed set of keys.

Honesty rules enforced here:

- Every field is derived from something that actually happened. Missing
  telemetry shows up as an explicit ``unavailable``/``None``/empty value,
  never as a fabricated number.
- ``supporting_evidence`` and ``contradicting_evidence`` are assembled from
  real signals (fired rules, feature availability, ARDE checks) — the two
  sides are always both present so an analyst sees the tension, not just
  the accusation.
- ``recommended_next_steps`` are *investigation* steps only. This engine is
  read-only: nothing here proposes or performs remediation.
"""

from __future__ import annotations

from typing import Any

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession
from algo.data_exfiltration.data_exfiltration.ml.versioning import (
    MODEL_NAME,
    MODEL_VERSION,
    RULE_VERSION,
    SCORING_VERSION,
)
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, SecurityFinding

OUTPUT_CONTRACT_VERSION = "finding-contract-3.0.0"

#: Human-readable phrasing for each transparent rule name in ``ml/rules.py``.
RULE_TEXT: dict[str, str] = {
    "volume_deviation_elevated": "Transferred volume/object/request counts deviate from this actor's baseline",
    "high_risk_destination": "Destination classifies as high-risk external",
    "unknown_external_destination": "Traffic leaves for an unknown external destination",
    "enumeration_pattern": "Many distinct objects enumerated across few prefixes",
    "access_pattern_novel": "Access pattern is novel for this actor/resource",
    "sensitive_data_access": "Sensitive data was in scope for the transfer",
    "unusual_time": "Activity falls outside the actor's normal hours",
    "unexpected_actor_resource": "Actor/resource pairing has no established history",
    "high_egress_ratio": "Measured egress ratio is unusually high",
}


def _strong_features(fset: BehavioralFeatureSet | None) -> list[dict[str, Any]]:
    """Features that are available AND elevated (>= 0.5) — the positive evidence."""
    if fset is None:
        return []
    out: list[dict[str, Any]] = []
    for name in (
        "volume_score",
        "object_count_score",
        "request_rate_score",
        "destination_score",
        "access_pattern_score",
        "sensitivity_score",
        "time_score",
        "actor_resource_score",
        "egress_score",
    ):
        feature = getattr(fset, name, None)
        if feature is None or feature.value is None:
            continue
        if feature.availability.value == "unavailable":
            continue
        if float(feature.value) >= 0.5:
            out.append({
                "feature": name,
                "value": round(float(feature.value), 6),
                "availability": feature.availability.value,
                "provenance": feature.provenance,
            })
    return out


def _unavailable_features(fset: BehavioralFeatureSet | None) -> list[str]:
    if fset is None:
        return []
    availability = fset.feature_availability or {}
    return sorted(name for name, state in availability.items() if state == "unavailable")


def _sensitivity_block(session: DataAccessSession, fset: BehavioralFeatureSet | None) -> dict[str, Any]:
    block: dict[str, Any] = {"available": False}
    summary = session.sensitivity_summary
    if summary is not None and summary.measurement is not None:
        block = {
            "available": True,
            "value": round(float(summary.value), 6) if summary.value is not None else None,
            "presence": summary.presence.value,
            "provenance": summary.measurement.provenance(),
        }
    elif summary is not None and summary.unavailable_reason:
        block = {"available": False, "reason": summary.unavailable_reason}
    if fset is not None and fset.sensitivity_score.value is not None:
        block.setdefault("score", round(float(fset.sensitivity_score.value), 6))
        block["score_availability"] = fset.sensitivity_score.availability.value
    return block


def _data_volume_block(session: DataAccessSession) -> dict[str, Any]:
    bytes_accessed = (
        session.bytes_accessed.value if session.bytes_accessed is not None else None
    )
    egress = (
        session.network_egress_bytes.value
        if session.network_egress_bytes is not None
        else None
    )
    return {
        "bytes_accessed": bytes_accessed,
        "bytes_accessed_presence": (
            session.bytes_accessed.presence.value if session.bytes_accessed is not None else "unavailable"
        ),
        "network_egress_bytes": egress,
        "network_egress_presence": (
            session.network_egress_bytes.presence.value
            if session.network_egress_bytes is not None
            else "unavailable"
        ),
        "objects_accessed": session.objects_accessed,
        "event_count": session.event_count,
        "request_count": session.request_count,
    }


def _temporal_block(session: DataAccessSession, fset: BehavioralFeatureSet | None) -> dict[str, Any]:
    start = session.start_time_epoch_ms
    end = session.end_time_epoch_ms
    duration = ((end or 0.0) - (start or 0.0)) / 1000.0 if (start is not None and end is not None) else None
    block: dict[str, Any] = {
        "start_time_epoch_ms": start,
        "end_time_epoch_ms": end,
        "duration_seconds": round(duration, 6) if duration is not None else None,
    }
    if fset is not None:
        block["time_score"] = fset.time_score.value
        block["time_availability"] = fset.time_score.availability.value
    return block


def _destination_block(session: DataAccessSession, fset: BehavioralFeatureSet | None) -> dict[str, Any]:
    block: dict[str, Any] = {
        "unique_destinations": list(session.unique_destinations),
        "unique_asns": list(session.unique_asns),
        "unique_countries": list(session.unique_countries),
    }
    if fset is not None:
        block["destination_score"] = fset.destination_score.value
        block["destination_class"] = (fset.destination_score.detail or {}).get("worst_class")
    return block


def _supporting_evidence(
    scored: ScoredSession | None,
    fset: BehavioralFeatureSet | None,
) -> list[str]:
    evidence: list[str] = []
    if scored is not None:
        for rule in scored.fired_rules:
            evidence.append(RULE_TEXT.get(rule, rule))
    for strong in _strong_features(fset):
        evidence.append(
            f"{strong['feature']}={strong['value']} ({strong['availability']}"
            + (f", {strong['provenance']}" if strong["provenance"] else "")
            + ")"
        )
    return evidence


def _contradicting_evidence(
    fset: BehavioralFeatureSet | None,
    arde: Any | None,
) -> list[str]:
    evidence: list[str] = []
    if fset is not None:
        if fset.baseline_quality < 0.5:
            evidence.append(
                f"Historical baseline is thin (baseline_quality={fset.baseline_quality}, scope={fset.baseline_scope_used})"
            )
        for name in _unavailable_features(fset):
            evidence.append(f"Feature {name} is unavailable (telemetry/history missing)")
    if arde is not None:
        checks = getattr(arde, "checks", None) or []
        for check in checks:
            status = getattr(getattr(check, "status", None), "value", None)
            if status in ("warning", "failed", "abstained"):
                evidence.append(f"ARDE check '{check.check_name}': {status} — {check.message}")
        for record in getattr(arde, "exceptions_applied", None) or []:
            evidence.append(
                "Legitimate-activity consideration: "
                f"{record.get('kind') or record.get('name') or 'exception'} "
                f"({record.get('decision') or 'recorded'})"
            )
    return evidence


def _recommended_next_steps(
    finding: SecurityFinding,
    scored: ScoredSession | None,
    fset: BehavioralFeatureSet | None,
    arde: Any | None,
) -> list[str]:
    """Investigation steps only — this engine never proposes remediation."""
    steps: list[str] = []
    status = getattr(getattr(arde, "validation_status", None), "value", None)
    level = getattr(getattr(arde, "robustness_level", None), "value", None)

    if status == "REJECTED":
        steps.append("No investigation required beyond the audit trail; ARDE rejected this candidate.")
    elif status == "REVIEW_REQUIRED":
        steps.append("Route to analyst review — ARDE could not fully corroborate or dismiss the candidate.")
    elif status == "PASSED_WITH_WARNINGS":
        steps.append("Review the recorded ARDE warnings alongside the evidence before disposition.")
    else:
        steps.append("Review the attached explanations and evidence for this finding.")

    if fset is not None and fset.baseline_quality < 0.5:
        steps.append("Corroborate with additional history — the behavioral baseline is still thin.")
    if level == "FRAGILE":
        steps.append("Treat the verdict as provisional; key evidence is thin or conflicting.")
    if not (scored.fired_rules if scored is not None else []):
        steps.append("Confirm which signal drove the score; no named rule fired.")

    steps.append("Compare the session against the actor's and resource's approved activity records.")
    return steps


def build_output_contract(
    finding: SecurityFinding,
    *,
    session: DataAccessSession,
    scored: ScoredSession | None = None,
    fset: BehavioralFeatureSet | None = None,
    arde: Any | None = None,
) -> dict[str, Any]:
    """Build the stable output contract for one finding.

    ``arde`` accepts an ARDE ``ValidationOutcome`` (or ``None``). All inputs
    beyond ``finding`` and ``session`` are optional so a Part 1 discovery
    finding still yields a well-formed (if less populated) contract.
    """
    model = scored.model if scored is not None else None
    robustness = getattr(arde, "robustness_score", None) if arde is not None else None
    versions = {
        "model_name": MODEL_NAME,
        "model_version": model.model_version if model is not None else MODEL_VERSION,
        "feature_version": model.feature_version if model is not None else None,
        "baseline_version": model.baseline_version if model is not None else None,
        "scoring_version": model.scoring_version if model is not None else SCORING_VERSION,
        "rule_version": model.rule_version if model is not None else RULE_VERSION,
    }

    return {
        "contract_version": OUTPUT_CONTRACT_VERSION,
        "finding_id": finding.finding_id,
        "detector_name": finding.detector_name,
        "finding_type": finding.finding_type.value,
        "severity": finding.severity.value if finding.severity is not None else None,
        "risk_score": finding.risk_score,
        "confidence": finding.confidence,
        "robustness_score": robustness,
        "robustness_level": getattr(getattr(arde, "robustness_level", None), "value", None),
        "validation_status": getattr(getattr(arde, "validation_status", None), "value", None),
        "actor": {"actor_id": session.actor_id, "provider": session.provider.value},
        "resource": {
            "resource_id": finding.resource_id,
            "resources_accessed": list(session.resources_accessed),
        },
        "session": {
            "session_id": session.session_id,
            "event_count": session.event_count,
            "read_event_count": session.read_event_count,
            "write_event_count": session.write_event_count,
            "enumerate_list_count": session.enumerate_list_count,
            "error_event_count": session.error_event_count,
        },
        "data_volume": _data_volume_block(session),
        "sensitivity": _sensitivity_block(session, fset),
        "destination": _destination_block(session, fset),
        "temporal_context": _temporal_block(session, fset),
        "signals": {
            "fired_rules": list(scored.fired_rules) if scored is not None else [],
            "contributions": dict(scored.contributions) if scored is not None else {},
            "rules_score": scored.rules_score if scored is not None else None,
            "anomaly_score": scored.anomaly_score if scored is not None else None,
            "supervised_score": scored.supervised_score if scored is not None else None,
            "confidence_state": scored.confidence_state if scored is not None else None,
            "missing_components": list(scored.missing_components) if scored is not None else [],
        },
        "supporting_evidence": _supporting_evidence(scored, fset),
        "contradicting_evidence": _contradicting_evidence(fset, arde),
        "baseline_quality": fset.baseline_quality if fset is not None else None,
        "baseline_scope_used": fset.baseline_scope_used if fset is not None else None,
        "feature_availability": dict(fset.feature_availability) if fset is not None else {},
        "versions": versions,
        # flat version keys: the documented contract fields, also grouped above
        "model_version": versions["model_version"],
        "feature_version": versions["feature_version"],
        "baseline_version": versions["baseline_version"],
        "scoring_version": versions["scoring_version"],
        "rule_version": versions["rule_version"],
        "recommended_next_steps": _recommended_next_steps(finding, scored, fset, arde),
    }


def attach_output_contract(
    finding: SecurityFinding,
    *,
    session: DataAccessSession,
    scored: ScoredSession | None = None,
    fset: BehavioralFeatureSet | None = None,
    arde: Any | None = None,
) -> dict[str, Any]:
    """Build the contract and store it under ``finding.metadata``. Returns it."""
    contract = build_output_contract(
        finding, session=session, scored=scored, fset=fset, arde=arde
    )
    finding.metadata["output_contract"] = contract
    return contract


def output_contract_of(finding: SecurityFinding) -> dict[str, Any] | None:
    """Retrieve the attached output contract, if any."""
    return finding.metadata.get("output_contract")
