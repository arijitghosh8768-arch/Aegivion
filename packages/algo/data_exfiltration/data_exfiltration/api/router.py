"""Minimal dependency-free router for the detector's REST surface.

The API is described as pure handlers (``service.DataExfiltrationService``)
and wired to paths here. Keeping routing separate from any web framework
means the endpoints are testable without a server, and the same handlers
can be mounted on FastAPI/Flask or exposed through the stdlib WSGI app in
``wsgi.py``.

Path patterns use ``{name}`` for a single segment and ``{name:path}`` for a
greedy match (needed because resource ids like ``s3://bucket`` contain
slashes).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

Handler = Callable[..., "APIResponse"]


@dataclass
class APIResponse:
    """Framework-neutral HTTP response."""

    status: int
    body: dict
    headers: dict[str, str] = field(default_factory=lambda: {"content-type": "application/json"})


@dataclass
class Route:
    method: str
    pattern: str
    handler: Handler
    _regex: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._regex = _compile(self.pattern)

    def match(self, method: str, path: str) -> dict[str, str] | None:
        if method.upper() != self.method.upper():
            return None
        m = self._regex.fullmatch(path)
        if m is None:
            return None
        return {k: _unescape(v) for k, v in m.groupdict().items()}


def _compile(pattern: str) -> re.Pattern[str]:
    parts: list[str] = []
    for token in re.split(r"(\{[^}]+\})", pattern):
        if token.startswith("{") and token.endswith("}"):
            name = token[1:-1]
            if ":" in name:
                name, kind = name.split(":", 1)
            else:
                kind = "segment"
            group = ".*" if kind == "path" else "[^/]+"
            parts.append(f"(?P<{name}>{group})")
        else:
            parts.append(re.escape(token))
    return re.compile("".join(parts))


def _unescape(value: str) -> str:
    from urllib.parse import unquote

    return unquote(value)


class Router:
    """Ordered route table with a single ``dispatch`` entry point."""

    def __init__(self) -> None:
        self._routes: list[Route] = []

    def add(self, method: str, pattern: str, handler: Handler) -> None:
        self._routes.append(Route(method=method, pattern=pattern, handler=handler))

    def routes(self) -> list[str]:
        return [f"{r.method} {r.pattern}" for r in self._routes]

    def dispatch(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        body: dict | None = None,
    ) -> APIResponse:
        path = path.rstrip("/") or "/"
        allowed: set[str] = set()
        for route in self._routes:
            params = route.match(method, path)
            if params is not None:
                return route.handler(**params, query=query or {}, body=body or {})
            # collect allowed methods for a 405 when the path matches a route
            # registered under a different method
            for other in ("GET", "POST", "PUT", "DELETE"):
                if other == method.upper():
                    continue
                if route._regex.fullmatch(path) is not None:
                    allowed.add(route.method.upper())
        if allowed:
            return APIResponse(
                status=405,
                body={
                    "error": {
                        "code": "method_not_allowed",
                        "message": f"method {method} not allowed",
                        "allowed": sorted(allowed),
                    }
                },
            )
        return APIResponse(
            status=404,
            body={"error": {"code": "not_found", "message": f"no route for {path}"}},
        )


__all__ = ["APIResponse", "Route", "Router"]
