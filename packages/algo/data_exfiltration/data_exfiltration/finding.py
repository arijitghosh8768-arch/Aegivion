"""Finding construction (discovery records only).

Part 1 emits ``finding_type = DATA_DISCOVERY`` records: structured,
human-reviewable documents of what was observed. No severity, no risk
score, no exfiltration verdict — those require Part 2 fusion. The ARDE
payload is attached so Threat Correlation can consume these records
unchanged later.
"""

from __future__ import annotations

import uuid
from typing import Any

from algo.data_exfiltration.data_exfiltration.schemas import (
    DataAccessSession,
    FindingSeverity,
    FindingType,
    Provider,
    SecurityFinding,
)

DETECTOR_NAME = "aegivion.data_exfiltration"


def build_discovery_finding(
    session: DataAccessSession,
    analyses: list,
    observed_at_epoch_ms: float | None = None,
    provider: Provider = Provider.AWS,
    account_id: str | None = None,
    region: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> SecurityFinding:
    """Build a DATA_DISCOVERY finding documenting observed session activity.

    ``analyses`` are AnalysisResult objects; their signals are embedded so
    analysts (and Threat Correlation) see the evidence, not just a verdict.
    """
    from datetime import datetime, timezone

    if observed_at_epoch_ms is None:
        observed_at_epoch_ms = session.end_time_epoch_ms or (
            datetime.now(timezone.utc).timestamp() * 1000.0
        )

    signals = {
        a.analysis_name: {"signals": a.signals, "risk_score": getattr(a, "risk_score", None)}
        for a in analyses
        if hasattr(a, "analysis_name")
    }
    risk_scores = {
        a.analysis_name: a.risk_score
        for a in analyses
        if getattr(a, "risk_score", None) is not None
    }

    description_parts = [
        f"Session {session.session_id} by actor {session.actor_id or 'unknown'} "
        f"accessed {len(session.resources_accessed)} resource(s) across "
        f"{session.event_count} event(s)."
    ]
    if risk_scores:
        description_parts.append(
            "Analysis stages produced risk signals: "
            + ", ".join(f"{name}={score}" for name, score in risk_scores.items())
        )
    else:
        description_parts.append(
            "No risk score is attached: risk fusion is not part of this release."
        )

    return _finish_finding(
        SecurityFinding(
            finding_id=f"find-{uuid.uuid4().hex[:12]}",
            detector_name=DETECTOR_NAME,
            finding_type=FindingType.DATA_DISCOVERY,
            severity=None,
            confidence=None,
            risk_score=None,
            title=f"Data activity discovery: {session.session_id}",
            description=" ".join(description_parts),
            observed_at_epoch_ms=observed_at_epoch_ms,
            provider=provider,
            account_id=account_id,
            region=region,
            actor_id=session.actor_id,
            resource_id=session.resources_accessed[0] if session.resources_accessed else None,
            session_id=session.session_id,
            arde=_build_arde(session, signals),
            metadata={"analyses": signals, "extra": extra_metadata or {}},
        ),
        session=session,
    )


def _finish_finding(finding: SecurityFinding, *, session: DataAccessSession) -> SecurityFinding:
    """Attach the stable output contract to a freshly built finding."""
    from algo.data_exfiltration.data_exfiltration.output_contract import attach_output_contract

    attach_output_contract(finding, session=session)
    return finding


def build_scored_finding(
    session: DataAccessSession,
    scored,
    analyses: list | None = None,
) -> SecurityFinding:
    """Build a finding from a scored session (Part 3).

    Carries the full model identity, the fused risk score, the separate
    confidence (with its explicit state), and the evidence-derived
    severity. ``scored`` is an ``ml.pipeline.ScoredSession``.
    """
    finding = build_discovery_finding(
        session,
        analyses or [],
        provider=session.provider,
    )
    finding.risk_score = scored.risk_score
    finding.confidence = scored.confidence_score
    finding.severity = FindingSeverity(scored.severity)
    finding.model = scored.as_metadata()
    finding.metadata["scoring"] = {
        "variant": scored.variant,
        "contributions": scored.contributions,
        "missing_components": scored.missing_components,
        "fired_rules": scored.fired_rules,
        "anomaly_score": scored.anomaly_score,
        "supervised_score": scored.supervised_score,
        "confidence_state": scored.confidence_state,
    }
    from algo.data_exfiltration.data_exfiltration.output_contract import attach_output_contract

    attach_output_contract(finding, session=session, scored=scored)
    return finding


def _build_arde(session: DataAccessSession, signals: dict[str, Any]) -> dict[str, Any]:
    """Assemble the ARDE (Aegivion Detection Event) payload.

    ARDE is intentionally evidence-complete: every block is present, with
    explicit unavailability markers where telemetry was missing.
    """
    bytes_block = (
        session.bytes_accessed.provenance() if session.bytes_accessed is not None
        else {"presence": "unavailable", "reason": "not measured"}
    )
    egress_block = (
        session.network_egress_bytes.provenance() if session.network_egress_bytes is not None
        else {"presence": "unavailable", "reason": "no correlated flow records"}
    )
    sensitivity_block = (
        session.sensitivity_summary.measurement.provenance()
        if session.sensitivity_summary is not None and session.sensitivity_summary.measurement is not None
        else {"presence": "unavailable", "reason": "no sensitivity enrichment"}
    )

    return {
        "arde_version": "1.0",
        "detector": DETECTOR_NAME,
        "session": {
            "session_id": session.session_id,
            "actor_id": session.actor_id,
            "provider": session.provider.value,
            "start_time_epoch_ms": session.start_time_epoch_ms,
            "end_time_epoch_ms": session.end_time_epoch_ms,
            "event_count": session.event_count,
            "request_count": session.request_count,
            "read_event_count": session.read_event_count,
            "write_event_count": session.write_event_count,
            "enumerate_list_count": session.enumerate_list_count,
            "error_event_count": session.error_event_count,
        },
        "resources": {
            "accessed": session.resources_accessed,
            "objects_accessed": session.objects_accessed,
        },
        "volumes": {
            "bytes_accessed": bytes_block,
            "network_egress_bytes": egress_block,
        },
        "network": {
            "unique_destinations": session.unique_destinations,
            "unique_asns": session.unique_asns,
            "unique_countries": session.unique_countries,
        },
        "sensitivity": sensitivity_block,
        "event_references": list(session.event_ids),
    }
