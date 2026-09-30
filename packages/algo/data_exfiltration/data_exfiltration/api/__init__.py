"""REST API surface for Algorithm #2 (framework-neutral, dependency-free).

Exposes five endpoints over analysis results:

    POST /api/v1/detections/data-exfiltration/analyze
    GET  /api/v1/detections/data-exfiltration/findings
    GET  /api/v1/data-resources/{resource_id}/profile
    GET  /api/v1/data-sessions/{session_id}
    GET  /api/v1/findings/{finding_id}/explanation

Handlers return :class:`APIResponse`; ``build_router`` wires routes and
``create_app`` returns a WSGI callable. Nothing here performs remediation.
"""

from __future__ import annotations

from .router import APIResponse, Route, Router
from .service import API_VERSION, DataExfiltrationService, build_router
from .wsgi import create_app

__all__ = [
    "APIResponse",
    "API_VERSION",
    "DataExfiltrationService",
    "Route",
    "Router",
    "build_router",
    "create_app",
]
