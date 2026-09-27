"""Typed exceptions for the Cloud Credential Compromise detector.

Engineering rule: telemetry is never silently dropped. Anything that cannot be
parsed raises a specific subclass of :class:`DetectionError` so the ingestion
pipeline can quarantine the record and surface the failure.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional


class DetectionError(Exception):
    """Base class for every error raised by the detection package."""

    def __init__(self, message: str, *, context: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = dict(context or {})

    def __str__(self) -> str:  # pragma: no cover - trivial
        if not self.context:
            return self.message
        rendered = ", ".join(f"{k}={v!r}" for k, v in sorted(self.context.items()))
        return f"{self.message} ({rendered})"


class ConfigurationError(DetectionError):
    """Raised when detector configuration is internally inconsistent."""


class MalformedEventError(DetectionError):
    """Raised when a raw provider event is missing or cannot be parsed."""

    def __init__(
        self,
        message: str,
        *,
        provider: str = "aws",
        missing_fields: Optional[list[str]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> None:
        merged: dict[str, Any] = {"provider": provider}
        if missing_fields:
            merged["missing_fields"] = ",".join(missing_fields)
        merged.update(context or {})
        super().__init__(message, context=merged)
        self.provider = provider
        self.missing_fields = list(missing_fields or [])


class UnsupportedEventSourceError(MalformedEventError):
    """Raised when an event source is recognised but out of scope for v1."""


class IdentityResolutionError(DetectionError):
    """Raised when an event cannot be attributed to a resolvable identity."""


class SessionBuildError(DetectionError):
    """Raised when session construction receives inconsistent input."""


class ProfileNotFoundError(DetectionError):
    """Raised when an identity profile is required but does not exist."""


class InsufficientHistoryError(DetectionError):
    """Raised when a personal baseline cannot be built (cold start)."""


class EnrichmentError(DetectionError):
    """Raised when IP/geo enrichment fails in a non-recoverable way."""


class NotImplementedYetError(DetectionError):
    """Explicit marker for algorithm stages that land in a later part.

    Used instead of returning fabricated values for stages that are not
    implemented yet.
    """
