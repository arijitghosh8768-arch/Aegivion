"""Framework-free REST API handlers — **Algorithm #3 final stage**.

The five endpoints mandated by the spec, implemented as pure
functions that return JSON-safe dicts. No HTTP framework is
imported: the transport layer (FastAPI, Flask, Azure Functions,
…) maps each handler to its route and serializes the dict:

========== ================================================== ============================
Method     Route                                            Handler
========== ================================================== ============================
POST       /api/v1/detections/cloud-destruction/analyze     :func:`analyze`
GET        /api/v1/detections/cloud-destruction/findings   :func:`list_findings`
GET        /api/v1/resources/{id}/protection-profile        :func:`get_protection_profile`
GET        /api/v1/destructive-sessions/{id}               :func:`get_destructive_session`
GET        /api/v1/findings/{id}/explanation               :func:`get_finding_explanation`
========== ================================================== ============================

Every handler is deterministic given its inputs and the
repository contents. Errors are returned as ``{"error": ...}``
dicts (the transport layer maps them to 4xx/5xx) — never as
raised exceptions across the handler boundary.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from algo.detection.cloud_destruction.config import DestructionDetectorConfig
from algo.detection.cloud_destruction.contract import (
    build_dashboard_data,
    build_finding_contract,
)
from algo.detection.cloud_destruction.detector import DestructionDetector
from algo.detection.cloud_destruction.explainability import Explanation
from algo.detection.cloud_destruction.resource_profile import ResourceProfileBuilder
from algo.detection.cloud_destruction.schemas import (
    DestructiveActivitySession,
    ResourceActivityEvent,
)
from algo.detection.cloud_destruction.storage import DestructionRepository

__all__ = [
    "ANALYZE_THRESHOLD",
    "analyze",
    "get_destructive_session",
    "get_finding_explanation",
    "get_protection_profile",
    "list_findings",
]

#: Risk score at/above which a persisted finding counts as a
#: destructive-activity finding in the analyze response.
ANALYZE_THRESHOLD = 0.35


# ---------------------------------------------------------------------- #
# POST /api/v1/detections/cloud-destruction/analyze
# ---------------------------------------------------------------------- #

def analyze(
    events: Sequence[ResourceActivityEvent],
    *,
    repository: DestructionRepository,
    config: Optional[DestructionDetectorConfig] = None,
) -> dict[str, Any]:
    """Run the detector on normalized telemetry and persist the result.

    The pipeline executed here is the acceptance-test chain:
    sessions are built, baselines compared, behavior scored,
    ARDE validates every finding, and the finding — with its
    explanation, contract and dashboard blocks — is preserved
    in ``repository`` before being returned.
    """
    events = list(events)
    detector = DestructionDetector(config)
    outcome = detector.detect(events)

    repository.save_events(events)
    repository.save_sessions(outcome.sessions)
    profiles = ResourceProfileBuilder(
        config=(config or DestructionDetectorConfig()).profile
    ).build_profiles(events)
    if profiles:
        repository.save_resource_profiles(list(profiles.values()))

    # Align the parallel detector outputs by session id (the
    # detector emits them in one pass, but keying by session
    # keeps the API robust to any internal ordering).
    sessions_by_id = {s.session_id: s for s in outcome.sessions}
    vectors_by_id = {v.session_id: v for v in outcome.feature_vectors}
    reports_by_id = {r.session_id: r for r in outcome.validation_reports}
    explanations_by_id = {
        e.session_id: e for e in outcome.explanations
    }
    event_by_id = {e.event_id: e for e in events}
    events_by_session = {
        s.session_id: [
            event_by_id[eid] for eid in s.event_ids if eid in event_by_id
        ]
        for s in outcome.sessions
    }

    contracts = [
        build_finding_contract(
            finding,
            sessions_by_id.get(finding.session_id),
            explanation=explanations_by_id.get(finding.session_id),
            report=reports_by_id.get(finding.session_id),
            vector=vectors_by_id.get(finding.session_id),
            events=events_by_session.get(finding.session_id, ()),
        )
        for finding in outcome.findings
    ]
    repository.save_findings(
        outcome.findings,
        explanations=outcome.explanations,
        contracts=contracts,
    )

    findings_payload: list[dict[str, Any]] = []
    destructive_count = 0
    for index, finding in enumerate(outcome.findings):
        payload = dict(
            repository.get_finding_payload(finding.finding_id) or {}
        )
        payload["dashboard"] = build_dashboard_data(
            contracts[index],
            session=sessions_by_id.get(finding.session_id),
            explanation=explanations_by_id.get(finding.session_id),
            vector=vectors_by_id.get(finding.session_id),
            events=events_by_session.get(finding.session_id, ()),
        )
        if finding.risk_score >= ANALYZE_THRESHOLD:
            destructive_count += 1
        findings_payload.append(payload)

    return {
        "events_accepted": len(events),
        "sessions_built": len(outcome.sessions),
        "findings_total": len(outcome.findings),
        "destructive_findings": destructive_count,
        "threshold": ANALYZE_THRESHOLD,
        "findings": findings_payload,
        "detector_versions": outcome.versions,
    }


# ---------------------------------------------------------------------- #
# GET /api/v1/detections/cloud-destruction/findings
# ---------------------------------------------------------------------- #

def list_findings(
    repository: DestructionRepository,
    *,
    limit: int = 1000,
) -> dict[str, Any]:
    """List persisted findings (newest first by observation time)."""
    findings = repository.list_findings(limit=limit)
    return {
        "count": len(findings),
        "findings": [finding.to_log_dict() for finding in findings],
    }


# ---------------------------------------------------------------------- #
# GET /api/v1/resources/{id}/protection-profile
# ---------------------------------------------------------------------- #

def get_protection_profile(
    repository: DestructionRepository,
    resource_id: str,
) -> dict[str, Any]:
    """Fetch the protection profile (baseline + recovery posture) of a resource."""
    profile = repository.get_resource_profile(resource_id)
    if profile is None:
        return {
            "error": "not_found",
            "resource_id": resource_id,
            "message": "no protection profile recorded for this resource",
        }
    return {
        "resource_id": resource_id,
        "profile": profile.model_dump(mode="json"),
    }


# ---------------------------------------------------------------------- #
# GET /api/v1/destructive-sessions/{id}
# ---------------------------------------------------------------------- #

def get_destructive_session(
    repository: DestructionRepository,
    session_id: str,
) -> dict[str, Any]:
    """Fetch one built destructive-activity session."""
    session: Optional[DestructiveActivitySession] = repository.get_session(
        session_id
    )
    if session is None:
        return {
            "error": "not_found",
            "session_id": session_id,
            "message": "no session recorded with this id",
        }
    return {
        "session_id": session_id,
        "session": session.model_dump(mode="json"),
    }


# ---------------------------------------------------------------------- #
# GET /api/v1/findings/{id}/explanation
# ---------------------------------------------------------------------- #

def get_finding_explanation(
    repository: DestructionRepository,
    finding_id: str,
) -> dict[str, Any]:
    """Fetch one finding's explanation, contract and dashboard blocks."""
    payload = repository.get_finding_payload(finding_id)
    if payload is None:
        return {
            "error": "not_found",
            "finding_id": finding_id,
            "message": "no finding recorded with this id",
        }

    result: dict[str, Any] = {
        "finding_id": finding_id,
        "explanation": payload.get("explanation"),
        "contract": payload.get("contract"),
    }

    # Rebuild the dashboard view from the persisted contract plus
    # the session and telemetry preserved alongside the finding.
    contract = payload.get("contract")
    if isinstance(contract, dict):
        session = repository.get_session(payload.get("session_id") or "")
        events: list[ResourceActivityEvent] = []
        if session is not None:
            events = [
                event
                for event in (
                    repository.get_event(event_id)
                    for event_id in session.event_ids
                )
                if event is not None
            ]
        explanation = payload.get("explanation")
        result["dashboard"] = build_dashboard_data(
            contract,
            session=session,
            explanation=(
                Explanation.model_validate(explanation)
                if isinstance(explanation, dict)
                else None
            ),
            events=events,
        )
    return result
