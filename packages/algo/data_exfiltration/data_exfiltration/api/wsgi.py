"""Stdlib WSGI adapter — real HTTP exposure with no extra dependencies.

``create_app`` returns a WSGI callable that dispatches to the router, so
the API can be served with any WSGI server (``wsgiref``, gunicorn, uwsgi)
or mounted under an existing framework's WSGI stack. Mounting on FastAPI
is equally possible by calling ``router.dispatch`` from a catch-all route.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs

from .router import APIResponse
from .service import DataExfiltrationService, build_router


def create_app(service: DataExfiltrationService | None = None) -> Callable:
    """Build a WSGI app around a service (fresh service when omitted)."""
    router = build_router(service)

    def app(environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        query = {k: v[0] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}

        body: dict[str, Any] = {}
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            length = 0
        if length:
            raw = environ["wsgi.input"].read(length)
            if raw:
                try:
                    body = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    return _finish(
                        APIResponse(
                            status=400,
                            body={"error": {"code": "bad_json", "message": "request body is not valid JSON"}},
                        ),
                        start_response,
                    )

        response = router.dispatch(method, path, query=query, body=body)
        return _finish(response, start_response)

    app.router = router  # type: ignore[attr-defined]
    return app


def _finish(response: Any, start_response: Callable) -> Iterable[bytes]:
    payload = json.dumps(response.body, sort_keys=True, default=str).encode("utf-8")
    reason = HTTPStatus(response.status).phrase if response.status in {s.value for s in HTTPStatus} else "OK"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(payload)),
        **{k.title(): v for k, v in response.headers.items() if k.lower() != "content-type"},
    }
    start_response(f"{response.status} {reason}", list(headers.items()))
    return [payload]


__all__ = ["create_app"]
