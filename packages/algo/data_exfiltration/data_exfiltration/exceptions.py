"""Algorithm #2 exceptions.

Layered hierarchy so callers can catch narrowly (single malformed event)
or broadly (whole normalization run failed).
"""

from __future__ import annotations


class DataExfiltrationError(Exception):
    """Base class for all Algorithm #2 errors."""


# ---------------------------------------------------------------------------
# Normalization errors
# ---------------------------------------------------------------------------


class NormalizationError(DataExfiltrationError):
    """Base class for normalization failures."""


class UnsupportedEventError(NormalizationError):
    """Event is structurally valid but not a data-plane event we support.

    Example: a CloudTrail management event (``ListBuckets``) routed to the
    normalizer by mistake. Callers should skip these without counting them
    as malformed.
    """


class MalformedEventError(NormalizationError):
    """Event is missing required fields or is structurally invalid.

    Carries the original raw payload so nothing is ever thrown away.
    """

    def __init__(self, message: str, raw_event: dict | None = None, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.raw_event = raw_event
        self.cause = cause


class UnknownProviderError(NormalizationError):
    """No normalizer is registered for the requested provider."""


class SchemaVersionError(NormalizationError):
    """Raw payload declares a schema version this build cannot read."""


# ---------------------------------------------------------------------------
# Provenance / measurement errors
# ---------------------------------------------------------------------------


class MeasurementConflictError(DataExfiltrationError):
    """Two measurements from incompatible sources were merged silently.

    Raised only where the model cannot represent the combination; ordinary
    conflicts are represented as MultiSourceMeasurements with a conflict flag.
    """


# ---------------------------------------------------------------------------
# Session / correlation errors
# ---------------------------------------------------------------------------


class SessionConstructionError(DataExfiltrationError):
    """Session construction failed (e.g. invalid window configuration)."""


class UncorrelatedEventError(DataExfiltrationError):
    """An event could not be assigned to any access session."""
