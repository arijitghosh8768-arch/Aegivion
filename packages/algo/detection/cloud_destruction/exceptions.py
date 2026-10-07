"""Typed exceptions for the Cloud Destructive Activity Detector.

Layered hierarchy so callers can catch narrowly (a single malformed record)
or broadly (a whole normalization run failed). Engineering rule: telemetry
is never silently dropped — anything unparseable raises a specific subclass
of :class:`CloudDestructionError` so the pipeline can quarantine it.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional


class CloudDestructionError(Exception):
    """Base class for every error raised by this detector."""

    def __init__(self, message: str, *, context: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = dict(context or {})

    def __str__(self) -> str:  # pragma: no cover - trivial
        if not self.context:
            return self.message
        rendered = ", ".join(f"{k}={v!r}" for k, v in sorted(self.context.items()))
        return f"{self.message} ({rendered})"


class ConfigurationError(CloudDestructionError):
    """Raised when detector configuration is internally inconsistent."""


class NormalizationError(CloudDestructionError):
    """Base class for normalization failures."""


class MalformedEventError(NormalizationError):
    """A raw provider event is missing required fields or cannot be parsed.

    Carries the raw payload reference so nothing is ever thrown away.
    """

    def __init__(
        self,
        message: str,
        *,
        provider: str = "aws",
        missing_fields: Optional[list[str]] = None,
        raw_event: Any = None,
        cause: Optional[BaseException] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> None:
        merged: dict[str, Any] = {"provider": provider}
        if missing_fields:
            merged["missing_fields"] = ",".join(missing_fields)
        merged.update(context or {})
        super().__init__(message, context=merged)
        self.provider = provider
        self.missing_fields = list(missing_fields or [])
        self.raw_event = raw_event
        self.cause = cause


class UnsupportedEventError(NormalizationError):
    """Structurally valid event that is out of scope for this detector.

    Example: a CloudTrail ``ConsoleLogin`` record routed to the destructive
    activity normalizer by mistake. Callers should skip these without
    counting them as malformed.
    """


class IngestBatchError(CloudDestructionError):
    """Raised when an ingestion batch cannot be processed at all."""


class SessionBuildError(CloudDestructionError):
    """Raised when session construction receives inconsistent input."""


class ProfileNotFoundError(CloudDestructionError):
    """Raised when a resource protection profile is required but missing."""


class InsufficientHistoryError(CloudDestructionError):
    """Raised when a baseline cannot be built (cold start). Part 2."""


class DatabaseError(CloudDestructionError):
    """Raised on persistence-layer failures (schema mismatch, IO, ...)."""


class NotImplementedYetError(CloudDestructionError):
    """Explicit marker for algorithm stages that land in a later part.

    Used instead of returning fabricated values for unimplemented stages —
    this is how we guarantee Part 1 never produces a fake destruction score.
    """


__all__ = [
    "CloudDestructionError",
    "ConfigurationError",
    "DatabaseError",
    "IngestBatchError",
    "InsufficientHistoryError",
    "MalformedEventError",
    "NormalizationError",
    "NotImplementedYetError",
    "ProfileNotFoundError",
    "SessionBuildError",
    "UnsupportedEventError",
]
