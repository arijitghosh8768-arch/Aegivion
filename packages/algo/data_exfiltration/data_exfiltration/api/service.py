"""REST API service for the Cloud Data Exfiltration Detector.

Five endpoints (all read-only over analysis results — nothing here mutates
cloud infrastructure):

    POST /api/v1/detections/data-exfiltration/analyze
    GET  /api/v1/detections/data-exfiltration/findings
    GET  /api/v1/data-resources/{resource_id:path}/profile
    GET  /api/v1/data-sessions/{session_id}
    GET  /api/v1/findings/{finding_id}/explanation

The handlers are plain functions returning :class:`APIResponse`; the
``Router`` maps paths to them. ``build_router`` is the one entry point the
WSGI adapter and tests both use.
"""

from __future__ import annotations

from typing import Any

from algo.data_exfiltration.data_exfiltration.config import DetectorConfig
from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector
from algo.data_exfiltration.data_exfiltration.output_contract import output_contract_of
from algo.data_exfiltration.data_exfiltration.storage import DetectionRepository

from .router import APIResponse, Router

API_VERSION = "v1"


class DataExfiltrationService:
    """Holds the detector + repository backing the API."""

    def __init__(
        self,
        detector: DataExfiltrationDetector | None = None,
        repository: DetectionRepository | None = None,
        config: DetectorConfig | None = None,
    ) -> None:
        self._repo = repository or DetectionRepository("sqlite:///:memory:")
        if detector is not None:
            self._detector = detector
        else:
            from algo.data_exfiltration.data_exfiltration.arde import ARDEValidator

            self._detector = DataExfiltrationDetector(
                config=config or DetectorConfig(),
                repository=self._repo,
                arde_validator=ARDEValidator(),
            )

    @property
    def repository(self) -> DetectionRepository:
        return self._repo

    # -- 1. analyze ---------------------------------------------------------

    def analyze(self, *, query: dict[str, str] | None = None, body: dict | None = None, **_: Any) -> APIResponse:
        payload = body or {}
        cloudtrail = payload.get("cloudtrail_records") or []
        flows = payload.get("vpc_flow_records") or []
        if not isinstance(cloudtrail, list) or not isinstance(flows, list):
            return _bad_request("cloudtrail_records and vpc_flow_records must be arrays")

        result = self._detector.process_events(
            cloudtrail_records=cloudtrail,
            vpc_flow_records=flows,
        )
        return APIResponse(
            status=200,
            body={
                "synthetic_capable": True,
                "stats": result.stats.as_dict(),
                "sessions": [s.model_dump(mode="json") for s in result.sessions],
                "findings": [f.model_dump(mode="json") for f in result.findings],
            },
        )

    # -- 2. findings --------------------------------------------------------

    def list_findings(self, *, query: dict[str, str] | None = None, body: dict | None = None, **_: Any) -> APIResponse:
        query = query or {}
        try:
            limit = int(query.get("limit", 100))
        except (TypeError, ValueError):
            return _bad_request("limit must be an integer")
        severity = query.get("severity")
        try:
            min_risk = float(query["min_risk"]) if query.get("min_risk") is not None else None
        except (TypeError, ValueError):
            return _bad_request("min_risk must be a number")

        findings = self._repo.list_findings(limit=max(1, min(limit, 1000)))
        out = []
        for finding in findings:
            if severity and (finding.severity is None or finding.severity.value != severity):
                continue
            if min_risk is not None and (finding.risk_score is None or finding.risk_score < min_risk):
                continue
            out.append(_finding_summary(finding))
        out.sort(key=lambda f: (f["risk_score"] is None, -(f["risk_score"] or 0.0), f["finding_id"]))
        return APIResponse(status=200, body={"count": len(out), "findings": out})

    # -- 3. resource profile ------------------------------------------------

    def resource_profile(self, *, resource_id: str, query: dict[str, str] | None = None, body: dict | None = None, **_: Any) -> APIResponse:
        profile = self._repo.get_resource_profile(resource_id)
        if profile is None:
            return _not_found("resource_profile", resource_id)
        return APIResponse(
            status=200,
            body={
                "resource": profile.model_dump(mode="json"),
                "note": "Observed history only; no verdict is stored on a resource profile.",
            },
        )

    # -- 4. session ---------------------------------------------------------

    def session(self, *, session_id: str, query: dict[str, str] | None = None, body: dict | None = None, **_: Any) -> APIResponse:
        session = next(
            (s for s in self._repo.list_sessions() if s.session_id == session_id), None
        )
        if session is None:
            return _not_found("session", session_id)
        findings = [f for f in self._repo.list_findings() if f.session_id == session_id]
        return APIResponse(
            status=200,
            body={
                "session": session.model_dump(mode="json"),
                "findings": [_finding_summary(f) for f in findings],
            },
        )

    # -- 5. finding explanation ---------------------------------------------

    def finding_explanation(self, *, finding_id: str, query: dict[str, str] | None = None, body: dict | None = None, **_: Any) -> APIResponse:
        finding = next(
            (f for f in self._repo.list_findings() if f.finding_id == finding_id), None
        )
        if finding is None:
            return _not_found("finding", finding_id)

        from algo.data_exfiltration.data_exfiltration.arde.integration import report_of

        return APIResponse(
            status=200,
            body={
                "finding": finding.model_dump(mode="json"),
                "output_contract": output_contract_of(finding),
                "arde_validation": finding.metadata.get("arde_validation"),
                "arde_explanation": finding.metadata.get("arde_explanation"),
                "report": report_of(finding),
            },
        )


def _finding_summary(finding: Any) -> dict[str, Any]:
    contract = output_contract_of(finding) or {}
    return {
        "finding_id": finding.finding_id,
        "detector_name": finding.detector_name,
        "finding_type": finding.finding_type.value,
        "severity": finding.severity.value if finding.severity is not None else None,
        "risk_score": finding.risk_score,
        "confidence": finding.confidence,
        "robustness_score": contract.get("robustness_score"),
        "validation_status": contract.get("validation_status"),
        "actor_id": finding.actor_id,
        "resource_id": finding.resource_id,
        "session_id": finding.session_id,
        "observed_at_epoch_ms": finding.observed_at_epoch_ms,
    }


def _bad_request(message: str) -> APIResponse:
    return APIResponse(status=400, body={"error": {"code": "bad_request", "message": message}})


def _not_found(kind: str, identifier: str) -> APIResponse:
    return APIResponse(
        status=404,
        body={"error": {"code": "not_found", "message": f"{kind} {identifier!r} not found"}},
    )


def build_router(service: DataExfiltrationService | None = None) -> Router:
    """Wire the five endpoints onto a router. Fresh service when omitted."""
    service = service or DataExfiltrationService()
    router = Router()
    router.add("POST", "/api/v1/detections/data-exfiltration/analyze", service.analyze)
    router.add("GET", "/api/v1/detections/data-exfiltration/findings", service.list_findings)
    router.add("GET", "/api/v1/data-resources/{resource_id:path}/profile", service.resource_profile)
    router.add("GET", "/api/v1/data-sessions/{session_id}", service.session)
    router.add("GET", "/api/v1/findings/{finding_id}/explanation", service.finding_explanation)
    return router


__all__ = ["API_VERSION", "DataExfiltrationService", "build_router"]
