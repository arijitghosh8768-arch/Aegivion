"""Normalizer robustness: missing fields must normalize with explicit unavailability."""

from __future__ import annotations

import pytest

from algo.data_exfiltration.data_exfiltration.measurement import MeasurementConfidence
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.schemas import ValuePresence

from .fixtures.missing import ALL, MISSING_BYTES, MISSING_SEVERAL, MISSING_SOURCE_IP


@pytest.mark.parametrize("record", ALL, ids=lambda r: r["eventID"])
def test_missing_fields_normalize(record) -> None:
    event = EventNormalizer().normalize_cloudtrail(record)
    assert event.event_id == record["eventID"]


def test_missing_bytes_are_unavailable() -> None:
    event = EventNormalizer().normalize_cloudtrail(MISSING_BYTES)
    assert event.bytes_accessed is None
    assert event.bytes_accessed_availability is MeasurementConfidence.UNAVAILABLE
    assert event.bytes_accessed_presence is ValuePresence.UNAVAILABLE


def test_missing_source_ip_is_none() -> None:
    event = EventNormalizer().normalize_cloudtrail(MISSING_SOURCE_IP)
    assert event.source_ip is None


def test_missing_several_fields_still_normalize() -> None:
    event = EventNormalizer().normalize_cloudtrail(MISSING_SEVERAL)
    assert event.user_agent is None
    assert event.source_ip is None
    assert event.bytes_accessed is None
    assert event.data_action is not None  # action knowledge survived
