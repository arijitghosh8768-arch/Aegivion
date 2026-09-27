"""API surface for Cloud Credential Compromise detections.

Only the router skeleton exists in Part 1. Endpoints are added once the
detector produces real findings, so the API can never return fabricated data.

Planned endpoints
-----------------
==============================================================  ============
``POST /api/v1/detections/credential-compromise/analyze``        analyze events
``GET  /api/v1/detections/credential-compromise/findings``        list findings
``GET  /api/v1/identities/{principal_id}/behavior``               behaviour view
``GET  /api/v1/identities/{principal_id}/baseline``               baseline view
``GET  /api/v1/identities/{principal_id}/timeline``               event timeline
``POST /api/v1/detections/credential-compromise/rebuild-baseline`` rebuild
``GET  /api/v1/detections/credential-compromise/explanation/{id}`` explain
==============================================================  ============

FastAPI is an optional dependency (``pip install aegivion[api]``); importing
this module without it raises a clear error rather than silently degrading.
"""

from __future__ import annotations

try:  # pragma: no cover - exercised only when the API extra is installed
    from fastapi import APIRouter
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "FastAPI is required for the credential compromise API. "
        "Install it with: pip install 'aegivion[api]'"
    ) from exc

router = APIRouter(prefix="/api/v1/detections/credential-compromise", tags=["credential-compromise"])

__all__ = ["router"]
