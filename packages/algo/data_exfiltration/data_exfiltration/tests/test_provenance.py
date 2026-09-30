"""Measurement/provenance primitive tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from algo.data_exfiltration.data_exfiltration.measurement import (
    MeasurementConfidence,
    MeasurementSource,
    MultiSourceMeasurement,
    SourceMeasurement,
    optional_measurement,
    simple_measurement,
    unavailable_measurement,
)
from algo.data_exfiltration.data_exfiltration.schemas import ValuePresence


def test_single_measurement_observed() -> None:
    m = simple_measurement(100.0, MeasurementSource.VPC_FLOW_LOG, MeasurementConfidence.OBSERVED)
    assert m.value == 100.0
    assert m.presence is ValuePresence.OBSERVED
    assert m.best_confidence is MeasurementConfidence.OBSERVED
    assert m.has_conflict is False


def test_empty_measurement_is_unavailable() -> None:
    m = MultiSourceMeasurement()
    assert m.value is None
    assert m.presence is ValuePresence.UNAVAILABLE


def test_conflict_detection() -> None:
    m = MultiSourceMeasurement(measurements=[
        SourceMeasurement(value=100.0, source=MeasurementSource.CLOUDTRAIL, confidence=MeasurementConfidence.ESTIMATED),
        SourceMeasurement(value=500.0, source=MeasurementSource.VPC_FLOW_LOG, confidence=MeasurementConfidence.OBSERVED),
    ])
    assert m.has_conflict is True
    assert m.value == 500.0  # max wins, conservatively


def test_no_conflict_within_tolerance() -> None:
    m = MultiSourceMeasurement(measurements=[
        SourceMeasurement(value=100.0, source=MeasurementSource.CLOUDTRAIL, confidence=MeasurementConfidence.ESTIMATED),
        SourceMeasurement(value=105.0, source=MeasurementSource.VPC_FLOW_LOG, confidence=MeasurementConfidence.OBSERVED),
    ])
    assert m.has_conflict is False


def test_add_keeps_immutability() -> None:
    a = simple_measurement(1.0, MeasurementSource.CLOUDTRAIL, MeasurementConfidence.ESTIMATED)
    b = a.add(SourceMeasurement(value=2.0, source=MeasurementSource.VPC_FLOW_LOG, confidence=MeasurementConfidence.OBSERVED))
    assert len(a.measurements) == 1
    assert len(b.measurements) == 2


def test_provenance_record_shape() -> None:
    m = simple_measurement(7.0, MeasurementSource.MACIE, MeasurementConfidence.EXTERNAL_ENRICHMENT, detail="x")
    prov = m.provenance()
    assert prov["sources"] == ["macie"]
    assert prov["confidence"] == "external_enrichment"
    assert prov["presence"] == "available"
    assert prov["contributions"][0]["detail"] == "x"


def test_optional_measurement_unavailable_reason() -> None:
    o = optional_measurement(None, None, None)
    assert o.presence is ValuePresence.UNAVAILABLE
    assert o.value is None
    assert "not provided" in o.unavailable_reason


def test_unavailable_measurement_helper() -> None:
    o = unavailable_measurement("no flows correlated")
    assert o.presence is ValuePresence.UNAVAILABLE
    assert o.unavailable_reason == "no flows correlated"


def test_source_measurement_requires_float_value() -> None:
    with pytest.raises(ValidationError):
        SourceMeasurement(value="abc", source=MeasurementSource.CLOUDTRAIL, confidence=MeasurementConfidence.ESTIMATED)
