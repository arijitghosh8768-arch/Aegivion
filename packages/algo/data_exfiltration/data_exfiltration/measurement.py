"""Measurement primitives: explicit provenance for every number.

The engine never silently merges measurements taken by different telemetry
sources, and never invents values. Everything is either:

- ``observed``            – measured directly by the source (e.g. VPC flow bytes)
- ``estimated``           – derived from other observations (e.g. CloudTrail size delta)
- ``external_enrichment`` – supplied by a third party (e.g. Macie sensitivity)
- ``unavailable``         – the source simply did not provide it

Confidence describes *how much the value should be trusted*; availability
describes *whether a value exists at all*. They are different axes and are
modeled separately.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MeasurementSource(str, Enum):
    """Where a measured value came from."""

    UNAVAILABLE = "unavailable"
    OBJECT_METADATA = "object_metadata"
    CLOUDTRAIL = "cloudtrail"
    VPC_FLOW_LOG = "vpc_flow_log"
    MACIE = "macie"
    DB_ACTIVITY = "db_activity"
    CONFIG_SERVICE = "config_service"
    NORMALIZER = "normalizer"
    AGGREGATION = "aggregation"
    EXTERNAL_ENRICHMENT = "external_enrichment"
    SYNTHETIC_FIXTURE = "synthetic_fixture"


class MeasurementConfidence(str, Enum):
    """How trustworthy a measured value is."""

    OBSERVED = "observed"
    ESTIMATED = "estimated"
    EXTERNAL_ENRICHMENT = "external_enrichment"
    AGGREGATED = "aggregated"
    UNAVAILABLE = "unavailable"


class ValuePresence(str, Enum):
    """Whether a value exists in the source telemetry at all.

    Mirrors the spec's required vocabulary: available / unavailable /
    estimated / observed.
    """

    AVAILABLE = "available"
    OBSERVED = "observed"
    ESTIMATED = "estimated"
    UNAVAILABLE = "unavailable"


class SourceMeasurement(BaseModel):
    """A single value contributed by one telemetry source."""

    model_config = ConfigDict(frozen=True)

    value: float
    source: MeasurementSource
    confidence: MeasurementConfidence
    detail: str | None = None


class MultiSourceMeasurement(BaseModel):
    """A measurement that may have been contributed by several sources.

    Values from incompatible sources are kept side by side; callers decide
    how to combine them (or not). ``has_conflict`` flags when sources
    disagree beyond a relative tolerance — merging is then the caller's
    explicit decision, never a silent one.
    """

    model_config = ConfigDict(frozen=True)

    measurements: list[SourceMeasurement] = Field(default_factory=list)
    conflict_tolerance: float = 0.10
    """Relative disagreement tolerance above which sources conflict."""

    @property
    def value(self) -> float | None:
        """The primary value: the single measurement, or the max when several.

        Max is the conservative choice for volume-style metrics. Returns
        None only when nothing was ever measured (callers should check
        ``presence`` first).
        """
        if not self.measurements:
            return None
        return max(m.value for m in self.measurements)

    @property
    def sources(self) -> list[MeasurementSource]:
        return [m.source for m in self.measurements]

    @property
    def best_confidence(self) -> MeasurementConfidence:
        """Highest-trust confidence among contributing measurements."""
        if not self.measurements:
            return MeasurementConfidence.UNAVAILABLE
        rank = {
            MeasurementConfidence.OBSERVED: 4,
            MeasurementConfidence.EXTERNAL_ENRICHMENT: 3,
            MeasurementConfidence.AGGREGATED: 2,
            MeasurementConfidence.ESTIMATED: 1,
            MeasurementConfidence.UNAVAILABLE: 0,
        }
        return max(self.measurements, key=lambda m: rank[m.confidence]).confidence

    @property
    def presence(self) -> ValuePresence:
        if not self.measurements:
            return ValuePresence.UNAVAILABLE
        if self.best_confidence == MeasurementConfidence.OBSERVED:
            return ValuePresence.OBSERVED
        if self.best_confidence in (MeasurementConfidence.ESTIMATED, MeasurementConfidence.AGGREGATED):
            return ValuePresence.ESTIMATED
        return ValuePresence.AVAILABLE

    @property
    def has_conflict(self) -> bool:
        if len(self.measurements) < 2:
            return False
        values = [m.value for m in self.measurements]
        lo, hi = min(values), max(values)
        if hi <= 0:
            return lo != hi
        return (hi - lo) / hi > self.conflict_tolerance

    def add(self, measurement: SourceMeasurement) -> "MultiSourceMeasurement":
        """Return a copy with an additional source measurement appended."""
        return MultiSourceMeasurement(
            measurements=[*self.measurements, measurement],
            conflict_tolerance=self.conflict_tolerance,
        )

    def provenance(self) -> dict[str, Any]:
        """Machine-readable provenance record for this measurement."""
        return {
            "sources": [s.value for s in self.sources],
            "confidence": self.best_confidence.value,
            "presence": self.presence.value,
            "value": self.value,
            "has_conflict": self.has_conflict,
            "contributions": [
                {
                    "value": m.value,
                    "source": m.source.value,
                    "confidence": m.confidence.value,
                    "detail": m.detail,
                }
                for m in self.measurements
            ],
        }


class OptionalMeasurements(BaseModel):
    """A value that is explicitly present or explicitly unavailable."""

    model_config = ConfigDict(frozen=True)

    measurement: MultiSourceMeasurement | None = None
    unavailable_reason: str | None = None

    @property
    def presence(self) -> ValuePresence:
        if self.measurement is None:
            return ValuePresence.UNAVAILABLE
        return self.measurement.presence

    @property
    def value(self) -> float | None:
        return self.measurement.value if self.measurement is not None else None


def simple_measurement(
    value: float,
    source: MeasurementSource,
    confidence: MeasurementConfidence,
    detail: str | None = None,
) -> MultiSourceMeasurement:
    """Build a single-source measurement with explicit provenance."""
    return MultiSourceMeasurement(
        measurements=[SourceMeasurement(value=value, source=source, confidence=confidence, detail=detail)]
    )


def unavailable_measurement(reason: str) -> OptionalMeasurements:
    """Build an explicit 'this was not available' marker with a reason."""
    return OptionalMeasurements(measurement=None, unavailable_reason=reason)


def optional_measurement(
    value: float | None,
    source: MeasurementSource | None,
    confidence: MeasurementConfidence | None,
    detail: str | None = None,
) -> OptionalMeasurements:
    """Build an optional measurement from possibly-missing pieces."""
    if value is None or source is None or confidence is None:
        return unavailable_measurement("value or provenance not provided by source")
    return OptionalMeasurements(
        measurement=simple_measurement(value=value, source=source, confidence=confidence, detail=detail)
    )
