"""Event provenance and field-availability model for Algorithm #3.

Core rule: **never invent values.** When telemetry does not provide a field,
the canonical event stores ``None`` (or an explicit "unavailable" marker) and
records *why* it is unavailable here, so downstream parts can reason about
evidence quality instead of guessing.

Three complementary mechanisms:

1. :class:`FieldAvailability` — per-field record of presence + reason.
2. :class:`DataProvenance` — where the event came from and how it traveled.
3. :class:`Measurement` — a derived value with source + confidence.

Availability and provenance are carried *on* the canonical event (see
``ResourceActivityEvent.feature_availability`` / ``.data_provenance``), keeping
the event self-describing for audit.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ValuePresence(str, Enum):
    """Whether a value is present, absent, or derived."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DERIVED = "derived"          # computed deterministically from raw telemetry
    ENRICHED = "enriched"        # supplied by an external catalog/enrichment


class UnavailableReason(str, Enum):
    """Standard machine-readable reasons a field can be unavailable."""

    NOT_IN_SOURCE = "not_in_source"              # provider did not emit it
    FIELD_NOT_APPLICABLE = "not_applicable"      # field meaningless for this action
    PARSE_FAILURE = "parse_failure"              # present but unparseable
    REDACTED = "redacted"                        # withheld by upstream policy
    NOT_ENABLED = "telemetry_not_enabled"        # e.g. data events not enabled
    ENRICHMENT_MISSING = "enrichment_missing"    # catalog lookup absent
    UNKNOWN = "unknown"


class FieldAvailability(BaseModel):
    """Availability record for a single canonical field."""

    model_config = ConfigDict(frozen=True)

    field: str = Field(min_length=1)
    presence: ValuePresence = ValuePresence.UNAVAILABLE
    reason: UnavailableReason = UnavailableReason.NOT_IN_SOURCE
    detail: Optional[str] = None

    @property
    def is_available(self) -> bool:
        return self.presence is not ValuePresence.UNAVAILABLE


class DataProvenance(BaseModel):
    """How a canonical event came to exist — full lineage, never invented."""

    model_config = ConfigDict(frozen=True)

    source_type: str = "cloudtrail"
    """Logical source: ``cloudtrail``, ``eventbridge``, ``service_event``,
    ``synthetic``, ``replay``."""

    ingestion_pipeline: str = "aws.cloudtrail_resource_activity"
    """Identifier of the normalizer that produced the event."""

    raw_record_index: Optional[int] = None
    """Index of the raw record within its batch/file."""

    raw_reference: Optional[str] = None
    """Pointer into the raw store (never a copy of the raw payload)."""

    received_at_epoch_ms: Optional[float] = None
    """When the pipeline received the record, if known."""

    is_replayed: bool = False
    """True when the record is a replay of historical telemetry."""

    replay_source: Optional[str] = None
    """Identifies the replay corpus when ``is_replayed`` is True."""

    is_synthetic: bool = False
    """True for fully synthetic fixture data (test/lab telemetry)."""

    generator: Optional[str] = None
    """Fixture/generator name for synthetic records."""

    normalizer_version: str = "1.0.0"
    transformation_notes: tuple[str, ...] = Field(default_factory=tuple)
    """Human-readable notes: defaults applied, warnings, coercions."""

    def with_note(self, note: str) -> "DataProvenance":
        """Return a copy with an additional transformation note."""
        return self.model_copy(update={"transformation_notes": (*self.transformation_notes, note)})


class MeasurementConfidence(str, Enum):
    """How much to trust a (derived) measurement."""

    OBSERVED = "observed"          # directly present in telemetry
    PARSED = "parsed"              # parsed from a provider field, trusted
    DERIVED = "derived"            # computed from observed fields
    ESTIMATED = "estimated"        # heuristic estimate, low trust
    UNAVAILABLE = "unavailable"


class Measurement(BaseModel):
    """A value with explicit provenance; ``value=None`` means unavailable."""

    model_config = ConfigDict(frozen=True)

    value: Optional[float] = None
    confidence: MeasurementConfidence = MeasurementConfidence.UNAVAILABLE
    source: Optional[str] = None
    reason: UnavailableReason = UnavailableReason.NOT_IN_SOURCE

    @property
    def is_available(self) -> bool:
        return self.value is not None


# --------------------------------------------------------------------------- #
# Feature provenance (Part 2)
# --------------------------------------------------------------------------- #


class FeatureProvenance(BaseModel):
    """How a derived behavioral feature was computed — full audit lineage.

    Deterministic Part 2 features record the method that produced them,
    the analyzers/baselines that contributed, and their measurement
    confidence. Part 3 scoring consumes this instead of guessing.
    """

    model_config = ConfigDict(frozen=True)

    method: Optional[str] = None
    """Deterministic computation method, e.g. ``"rate_ratio_to_factor"``."""
    contributors: tuple[str, ...] = Field(default_factory=tuple)
    """Analyzer / baseline identifiers that produced the value."""
    confidence: MeasurementConfidence = MeasurementConfidence.DERIVED
    baseline_quality: Optional[str] = None
    """Baseline quality at computation time, when a baseline contributed."""
    baseline_version: Optional[str] = None
    """Version of the baseline the value was computed against."""


# --------------------------------------------------------------------------- #
# Measured feature values (Part 2)
# --------------------------------------------------------------------------- #


class MeasuredValue(BaseModel):
    """A single derived feature: value + availability + provenance.

    ``value=None`` always pairs with ``available=False`` and a machine-
    readable reason, so consumers can distinguish "evidence says calm"
    (a real 0.0) from "no evidence at all" (``None``).
    """

    model_config = ConfigDict(frozen=True)

    value: Optional[float] = None
    available: bool = False
    reason: Optional[str] = None
    confidence: MeasurementConfidence = MeasurementConfidence.UNAVAILABLE
    method: Optional[str] = None
    """Deterministic computation method, e.g. ``"rate_ratio_to_factor"``."""
    contributors: tuple[str, ...] = Field(default_factory=tuple)
    """Analyzer / baseline identifiers that produced this value."""
    raw: dict[str, Any] = Field(default_factory=dict)
    """Raw counters behind the value (audit trail back to telemetry)."""

    @staticmethod
    def unavailable(
        reason: str,
        *,
        contributors: tuple[str, ...] = (),
    ) -> "MeasuredValue":
        return MeasuredValue(
            value=None,
            available=False,
            reason=reason,
            confidence=MeasurementConfidence.UNAVAILABLE,
            contributors=contributors,
        )

    @staticmethod
    def measured(
        value: float,
        *,
        method: str,
        contributors: tuple[str, ...] = (),
        raw: Optional[dict[str, Any]] = None,
        confidence: MeasurementConfidence = MeasurementConfidence.DERIVED,
    ) -> "MeasuredValue":
        return MeasuredValue(
            value=value,
            available=True,
            reason=None,
            confidence=confidence,
            method=method,
            contributors=contributors,
            raw=dict(raw or {}),
        )


# --------------------------------------------------------------------------- #
# Availability builder
# --------------------------------------------------------------------------- #


class AvailabilityTracker:
    """Accumulates per-field availability while a normalizer runs.

    Usage::

        tracker = AvailabilityTracker()
        tracker.available("actor_id")
        tracker.unavailable("object_key", UnavailableReason.NOT_APPLICABLE)
        availability = tracker.to_tuple()
    """

    def __init__(self) -> None:
        self._records: dict[str, FieldAvailability] = {}

    def available(self, field: str, *, derived: bool = False, enriched: bool = False) -> None:
        if derived:
            presence = ValuePresence.DERIVED
        elif enriched:
            presence = ValuePresence.ENRICHED
        else:
            presence = ValuePresence.AVAILABLE
        self._records[field] = FieldAvailability(
            field=field, presence=presence, reason=UnavailableReason.NOT_IN_SOURCE
        )

    def unavailable(
        self,
        field: str,
        reason: UnavailableReason = UnavailableReason.NOT_IN_SOURCE,
        detail: Optional[str] = None,
    ) -> None:
        self._records[field] = FieldAvailability(
            field=field, presence=ValuePresence.UNAVAILABLE, reason=reason, detail=detail
        )

    def merge(self, other: "AvailabilityTracker") -> None:
        """Merge ``other`` into this tracker; existing entries win."""
        for field, record in other._records.items():  # noqa: SLF001 - same class
            self._records.setdefault(field, record)

    def record_many(
        self,
        fields: Iterable[str],
        *,
        present: Mapping[str, bool],
        reason: UnavailableReason = UnavailableReason.NOT_IN_SOURCE,
    ) -> None:
        for field in fields:
            if present.get(field, False):
                self.available(field)
            else:
                self.unavailable(field, reason)

    def to_tuple(self) -> tuple[FieldAvailability, ...]:
        return tuple(self._records[field] for field in sorted(self._records))

    def to_dict(self) -> dict[str, FieldAvailability]:
        return dict(self._records)


def build_availability(
    fields: Iterable[str],
    *,
    present: Mapping[str, Any],
) -> tuple[FieldAvailability, ...]:
    """One-shot helper: mark each field available/unavailable from ``present``.

    ``present`` maps field name -> truthy when the normalizer extracted it.
    """
    tracker = AvailabilityTracker()
    for field in fields:
        if present.get(field):
            tracker.available(field)
        else:
            tracker.unavailable(field)
    return tracker.to_tuple()


def availability_for_missing(
    fields: Iterable[str],
    reason: UnavailableReason = UnavailableReason.NOT_IN_SOURCE,
) -> tuple[FieldAvailability, ...]:
    """Mark every listed field unavailable for ``reason``."""
    tracker = AvailabilityTracker()
    for field in fields:
        tracker.unavailable(field, reason)
    return tracker.to_tuple()


__all__ = [
    "AvailabilityTracker",
    "DataProvenance",
    "FeatureProvenance",
    "FieldAvailability",
    "MeasuredValue",
    "Measurement",
    "MeasurementConfidence",
    "UnavailableReason",
    "ValuePresence",
    "availability_for_missing",
    "build_availability",
]
