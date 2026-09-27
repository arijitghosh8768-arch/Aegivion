"""Aegivion detection API - **Part 4 (integration)**.

Framework-free HTTP layer so the detection engine can be embedded anywhere;
an optional :func:`create_fastapi_app` adapter exposes the same routes when
FastAPI is installed (it is an optional dependency: ``pip install .[api]``).

Endpoints (per the research brief):

* ``POST /api/v1/detections/credential-compromise/analyze``
* ``GET  /api/v1/detections/credential-compromise/findings``
* ``GET  /api/v1/identities/{id}/behavior``
* ``GET  /api/v1/identities/{id}/timeline``
* ``GET  /api/v1/findings/{id}/explanation``

Safety: these endpoints expose detection results and evidence only. There is
no endpoint that can disable users, revoke credentials or mutate cloud state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from detection.credential_compromise.config import DetectorConfig
from detection.credential_compromise.detector import (
    CredentialCompromiseDetector,
    DetectionMode,
)
from detection.credential_compromise.exceptions import DetectionError
from detection.credential_compromise.schemas import IdentityActivityEvent

# --------------------------------------------------------------------------- #
# Minimal HTTP primitives (framework-free)
# --------------------------------------------------------------------------- #


@dataclass
class Request:
    method: str
    path: str
    params: dict[str, str] = field(default_factory=dict)
    body: Optional[dict] = None


@dataclass
class Response:
    status: int
    body: dict

    @classmethod
    def ok(cls, body: dict) -> "Response":
        return cls(200, body)

    @classmethod
    def not_found(cls, message: str) -> "Response":
        return cls(404, {"error": message})

    @classmethod
    def bad_request(cls, message: str) -> "Response":
        return cls(400, {"error": message})


# --------------------------------------------------------------------------- #
# In-memory finding store (swap for storage.finding_repository in production)
# --------------------------------------------------------------------------- #


class FindingStore:
    """Keeps finalized findings and per-identity evidence for the API."""

    def __init__(self) -> None:
        self._findings: dict[str, dict] = {}
        self._by_identity: dict[str, list[str]] = {}

    def add(self, finding: dict) -> str:
        finding_id = str(finding["finding_id"])
        self._findings[finding_id] = finding
        identity = str(finding["identity_key"])
        self._by_identity.setdefault(identity, []).append(finding_id)
        return finding_id

    def get(self, finding_id: str) -> Optional[dict]:
        return self._findings.get(finding_id)

    def list(self) -> list[dict]:
        return list(self._findings.values())

    def for_identity(self, identity_key: str) -> list[dict]:
        ids = self._by_identity.get(identity_key, [])
        return [self._findings[fid] for fid in ids]


# --------------------------------------------------------------------------- #
# Application service
# --------------------------------------------------------------------------- #


class DetectionApp:
    """Wires the detector to request handling with its own evidence store."""

    def __init__(
        self,
        detector: Optional[CredentialCompromiseDetector] = None,
        config: Optional[DetectorConfig] = None,
    ) -> None:
        self.config = config or DetectorConfig()
        self.detector = detector or CredentialCompromiseDetector(config=self.config)
        self.store = FindingStore()

    # -- POST /analyze ---------------------------------------------------- #

    def analyze(self, body: Optional[dict]) -> Response:
        """Analyze one canonical event (or a raw CloudTrail record).

        Accepts either an ``IdentityActivityEvent``-shaped body or a raw
        CloudTrail record (normalized through the Part 1 adapter). The
        response always contains the risk/confidence/robustness trio and, for
        findings, the full evidence bundle. Destructive actions are not
        possible through this endpoint by construction.
        """
        if not isinstance(body, dict) or not body:
            return Response.bad_request("request body must be a JSON object")
        try:
            event = self._coerce_event(body)
        except DetectionError as exc:
            return Response.bad_request(f"unusable event: {exc}")
        except Exception as exc:  # malformed payload shapes
            return Response.bad_request(f"unusable event: {type(exc).__name__}")

        result = self.detector.detect(event, mode=DetectionMode.REAL_TIME)
        payload: dict[str, Any] = {
            "event_id": event.event_id,
            "risk_score": result.risk,
            "confidence": result.confidence,
            "severity": result.severity.value,
            "is_finding": result.is_finding,
            "signals": [
                s.to_dict() if hasattr(s, "to_dict") else dict(s) for s in result.signals
            ],
            "arde_status": result.arde.validation_status if result.arde else None,
            "robustness_score": result.arde.robustness_score if result.arde else None,
            "distinguishes": {
                "anomaly": bool(result.signals),
                "risk": result.risk,
                "confidence": result.confidence,
                "validated_finding": result.is_finding,
            },
        }
        if result.finding is not None:
            finding_id = self.store.add(result.finding)
            payload["finding_id"] = finding_id
            payload["finding"] = result.finding
        return Response.ok(payload)

    # -- GET /findings ------------------------------------------------------ #

    def list_findings(self) -> Response:
        findings = self.store.list()
        return Response.ok(
            {
                "count": len(findings),
                "findings": [
                    {
                        "finding_id": f["finding_id"],
                        "identity_key": f["identity_key"],
                        "severity": f["severity"],
                        "risk_score": f["risk_score"],
                        "confidence": f["confidence"],
                        "robustness_score": f["robustness_score"],
                        "validation_status": f["validation_status"],
                    }
                    for f in findings
                ],
            }
        )

    # -- GET /identities/{id}/behavior -------------------------------------- #

    def identity_behavior(self, identity_key: str) -> Response:
        window = self.config.baseline.primary_window_days
        profile = self.detector._profiles.get((identity_key, window))
        if profile is None:
            return Response.not_found(f"no baseline for identity {identity_key}")
        return Response.ok(
            {
                "identity_key": identity_key,
                "window_days": profile.window_days,
                "baseline_quality": profile.baseline_quality.value,
                "baseline_version": profile.baseline_version,
                "event_count": profile.event_count,
                "normal_hours": profile.normal_hours,
                "normal_countries": profile.normal_countries,
                "normal_services": profile.normal_services,
                "normal_user_agents": profile.normal_user_agents,
                "read_write_ratio": profile.read_write_ratio,
                "normal_privilege_level": profile.normal_privilege_level,
            }
        )

    # -- GET /identities/{id}/timeline ---------------------------------------- #

    def identity_timeline(self, identity_key: str) -> Response:
        findings = self.store.for_identity(identity_key)
        return Response.ok(
            {
                "identity_key": identity_key,
                "finding_count": len(findings),
                "timeline": [
                    {
                        "finding_id": f["finding_id"],
                        "first_seen": f["first_seen"],
                        "last_seen": f["last_seen"],
                        "severity": f["severity"],
                        "risk_score": f["risk_score"],
                        "top_contributors": f.get("explanation", {}).get(
                            "top_contributors", []
                        ),
                    }
                    for f in findings
                ],
            }
        )

    # -- GET /findings/{id}/explanation ---------------------------------------- #

    def finding_explanation(self, finding_id: str) -> Response:
        finding = self.store.get(finding_id)
        if finding is None:
            return Response.not_found(f"unknown finding {finding_id}")
        return Response.ok(
            {
                "finding_id": finding_id,
                "explanation": finding.get("explanation", {}),
                "arde": finding.get("arde", {}),
                "supporting_features": finding.get("supporting_features", []),
                "contradicting_features": finding.get("contradicting_features", []),
                "recommended_next_steps": finding.get("recommended_next_steps", []),
                "ATTACK_mapping": finding.get("ATTACK_mapping", []),
            }
        )

    # -- helpers ---------------------------------------------------------------- #

    @staticmethod
    def _coerce_event(body: dict) -> IdentityActivityEvent:
        """Canonical event body, or a raw CloudTrail record."""
        if {"event_id", "timestamp", "principal_id", "event_source", "event_name"} <= set(body):
            return IdentityActivityEvent(**body)
        from ingestion.aws.cloudtrail import CloudTrailNormalizer

        return CloudTrailNormalizer().normalize(body)


# --------------------------------------------------------------------------- #
# Router
# --------------------------------------------------------------------------- #

_ANALYZE_PATH = "/api/v1/detections/credential-compromise/analyze"
_FINDINGS_PATH = "/api/v1/detections/credential-compromise/findings"
_BEHAVIOR_RE = re.compile(r"^/api/v1/identities/(?P<identity>.+)/behavior$")
_TIMELINE_RE = re.compile(r"^/api/v1/identities/(?P<identity>.+)/timeline$")
_EXPLANATION_RE = re.compile(r"^/api/v1/findings/(?P<finding_id>.+)/explanation$")


class Router:
    """Dispatches requests to a :class:`DetectionApp`."""

    def __init__(self, app: Optional[DetectionApp] = None) -> None:
        self.app = app or DetectionApp()

    def handle(self, request: Request) -> Response:
        if request.method == "POST" and request.path == _ANALYZE_PATH:
            return self.app.analyze(request.body)
        if request.method == "GET" and request.path == _FINDINGS_PATH:
            return self.app.list_findings()
        behavior = _BEHAVIOR_RE.match(request.path)
        if request.method == "GET" and behavior:
            return self.app.identity_behavior(behavior.group("identity"))
        timeline = _TIMELINE_RE.match(request.path)
        if request.method == "GET" and timeline:
            return self.app.identity_timeline(timeline.group("identity"))
        explanation = _EXPLANATION_RE.match(request.path)
        if request.method == "GET" and explanation:
            return self.app.finding_explanation(explanation.group("finding_id"))
        return Response.not_found(f"no route for {request.method} {request.path}")


# --------------------------------------------------------------------------- #
# Optional FastAPI adapter
# --------------------------------------------------------------------------- #


def create_fastapi_app(app: Optional[DetectionApp] = None):
    """Return a FastAPI application exposing the same routes.

    Raises ``ImportError`` with guidance when FastAPI is not installed.
    """
    try:
        from fastapi import FastAPI, Request as FastApiRequest
        from fastapi.responses import JSONResponse
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise ImportError(
            "FastAPI is not installed; install with `pip install .[api]` or use "
            "the framework-free Router directly"
        ) from exc

    detection_app = app or DetectionApp()
    router = Router(detection_app)
    fastapp = FastAPI(title="Aegivion Detection API", version="1.0.0")

    @fastapp.post(_ANALYZE_PATH)
    async def analyze(body: dict):  # pragma: no cover - requires FastAPI
        response = router.handle(Request(method="POST", path=_ANALYZE_PATH, body=body))
        return JSONResponse(status_code=response.status, content=response.body)

    @fastapp.get(_FINDINGS_PATH)
    async def findings():  # pragma: no cover - requires FastAPI
        response = router.handle(Request(method="GET", path=_FINDINGS_PATH))
        return JSONResponse(status_code=response.status, content=response.body)

    @fastapp.get("/api/v1/identities/{identity}/behavior")
    async def behavior(identity: str):  # pragma: no cover
        response = router.handle(
            Request(method="GET", path=f"/api/v1/identities/{identity}/behavior")
        )
        return JSONResponse(status_code=response.status, content=response.body)

    @fastapp.get("/api/v1/identities/{identity}/timeline")
    async def timeline(identity: str):  # pragma: no cover
        response = router.handle(
            Request(method="GET", path=f"/api/v1/identities/{identity}/timeline")
        )
        return JSONResponse(status_code=response.status, content=response.body)

    @fastapp.get("/api/v1/findings/{finding_id}/explanation")
    async def explanation(finding_id: str):  # pragma: no cover
        response = router.handle(
            Request(method="GET", path=f"/api/v1/findings/{finding_id}/explanation")
        )
        return JSONResponse(status_code=response.status, content=response.body)

    _ = FastApiRequest  # imported for typing parity; silence unused warnings
    return fastapp


__all__ = [
    "DetectionApp",
    "FindingStore",
    "Request",
    "Response",
    "Router",
    "create_fastapi_app",
]
