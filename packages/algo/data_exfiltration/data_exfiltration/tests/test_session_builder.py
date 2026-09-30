"""Session builder tests: gap windows, aggregation, honest aggregates."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from algo.data_exfiltration.data_exfiltration.config import DetectorConfig, SessionConfig
from algo.data_exfiltration.data_exfiltration.exceptions import SessionConstructionError
from algo.data_exfiltration.data_exfiltration.measurement import (
    MeasurementConfidence,
    MeasurementSource,
    simple_measurement,
)
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.schemas import DataActivityEvent, Provider
from algo.data_exfiltration.data_exfiltration.session import SessionBuilder

from .fixtures.cloudtrail_records import S3_GET, S3_GET_ROLE, S3_LIST


def _ts(iso: str) -> DataActivityEvent:
    record = {**S3_GET, "eventTime": iso}
    return EventNormalizer().normalize_cloudtrail(record)


def _ts_epoch(ms: float) -> DataActivityEvent:
    record = {**S3_GET, "eventTime": datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    return EventNormalizer().normalize_cloudtrail(record)


class TestWindowing:
    def test_events_within_gap_form_one_session(self) -> None:
        builder = SessionBuilder(DetectorConfig(session=SessionConfig(inactivity_gap=600)))
        base = datetime(2024, 11, 14, 3, 0, tzinfo=timezone.utc)
        events = [_ts((base + timedelta(seconds=i * 60)).strftime("%Y-%m-%dT%H:%M:%SZ")) for i in range(5)]
        closed = builder.add_events(events)
        assert closed == []
        sessions = builder.flush()
        assert len(sessions) == 1
        assert sessions[0].event_count == 5

    def test_gap_opens_new_session(self) -> None:
        builder = SessionBuilder(DetectorConfig(session=SessionConfig(inactivity_gap=60)))
        base = datetime(2024, 11, 14, 3, 0, tzinfo=timezone.utc)
        e1 = _ts(base.strftime("%Y-%m-%dT%H:%M:%SZ"))
        e2 = _ts((base + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        closed = builder.add_events([e1, e2])
        assert len(closed) == 1
        assert closed[0].event_count == 1
        sessions = builder.flush()
        # flush returns everything built since the last flush: the session
        # closed by the gap (from algo.data_exfiltration.ingestion) plus the still-open second one
        assert len(sessions) == 2
        assert {s.event_count for s in sessions} == {1}

    def test_flush_closes_open_sessions(self) -> None:
        builder = SessionBuilder()
        builder.add_event(_ts("2024-11-14T03:00:00Z"))
        sessions = builder.flush()
        assert len(sessions) == 1
        assert sessions[0].end_time_epoch_ms is not None

    def test_max_duration_closes_session(self) -> None:
        builder = SessionBuilder(DetectorConfig(session=SessionConfig(inactivity_gap=3600, max_session_duration=120)))
        base_ms = datetime(2024, 11, 14, 3, 0, tzinfo=timezone.utc).timestamp() * 1000
        closed = builder.add_events([_ts_epoch(base_ms), _ts_epoch(base_ms + 180_000)])
        assert len(closed) == 1  # duration cap forces close

    def test_event_without_timestamp_rejected(self) -> None:
        # model_construct bypasses validation to simulate a bad event
        event = DataActivityEvent.model_construct(
            event_id="x",
            provider=Provider.AWS,
            event_time_epoch_ms=None,
        )
        builder = SessionBuilder()
        with pytest.raises(SessionConstructionError):
            builder.add_event(event)

    def test_separate_actors_separate_sessions(self) -> None:
        builder = SessionBuilder()
        e1 = EventNormalizer().normalize_cloudtrail({**S3_GET, "eventTime": "2024-11-14T03:00:00Z"})
        role_record = {**S3_GET_ROLE, "eventTime": "2024-11-14T03:00:30Z"}
        e2 = EventNormalizer().normalize_cloudtrail(role_record)
        builder.add_events([e1, e2])
        sessions = builder.flush()
        assert len(sessions) == 2
        assert {s.actor_id for s in sessions} == {e1.actor_id, e2.actor_id}


class TestAggregation:
    def test_byte_categories_stay_separate(self) -> None:
        """CloudTrail-estimated and flow-observed bytes must not merge."""
        builder = SessionBuilder()
        e1 = EventNormalizer().normalize_cloudtrail({**S3_GET, "eventTime": "2024-11-14T03:00:00Z"})
        # inject a flow-style contribution via network_bytes on a second event
        e2 = EventNormalizer().normalize_cloudtrail({**S3_LIST, "eventTime": "2024-11-14T03:01:00Z"})
        e2.network_bytes = simple_measurement(
            999.0, MeasurementSource.VPC_FLOW_LOG, MeasurementConfidence.OBSERVED
        )
        builder.add_events([e1, e2])
        (session,) = builder.flush()

        agg = session.bytes_accessed
        assert agg is not None
        sources = {m.source for m in agg.measurements}
        assert sources == {MeasurementSource.CLOUDTRAIL}
        # egress kept its own channel
        assert session.network_egress_bytes is not None
        assert session.network_egress_bytes.value == 999.0

    def test_destinations_and_counts(self) -> None:
        builder = SessionBuilder()
        e1 = EventNormalizer().normalize_cloudtrail({**S3_GET, "eventTime": "2024-11-14T03:00:00Z"})
        e2 = EventNormalizer().normalize_cloudtrail({**S3_LIST, "eventTime": "2024-11-14T03:00:10Z"})
        e1.destination_ip = "198.51.100.9"
        e2.destination_ip = "198.51.100.9"
        builder.add_events([e1, e2])
        (session,) = builder.flush()
        assert session.unique_destinations == ["198.51.100.9"]
        assert session.request_count == 2
        assert session.event_count == 2
        assert session.read_event_count == 2
        assert session.enumerate_list_count == 1

    def test_empty_session_has_zero_aggregates(self) -> None:
        """No bytes measured -> aggregate absent, not zero-fabricated."""
        builder = SessionBuilder()
        event = EventNormalizer().normalize_cloudtrail({**S3_LIST, "eventTime": "2024-11-14T03:00:00Z"})
        builder.add_events([event])
        (session,) = builder.flush()
        assert session.bytes_accessed is None
        assert session.network_egress_bytes is None
        assert session.objects_accessed == 0
        assert session.sensitivity_summary is not None
        assert session.sensitivity_summary.presence.value == "unavailable"

    def test_sensitivity_summary_takes_max(self) -> None:
        from algo.data_exfiltration.data_exfiltration.schemas import SensitivityLevel

        builder = SessionBuilder()
        e1 = EventNormalizer().normalize_cloudtrail({**S3_GET, "eventTime": "2024-11-14T03:00:00Z"})
        e2 = EventNormalizer().normalize_cloudtrail({**S3_GET, "eventTime": "2024-11-14T03:00:20Z"})
        e1.sensitivity_level = SensitivityLevel.PII
        e1.sensitivity_source = "macie"
        e1.sensitivity_score = simple_measurement(0.8, MeasurementSource.MACIE, MeasurementConfidence.EXTERNAL_ENRICHMENT)
        e2.sensitivity_level = SensitivityLevel.PII
        e2.sensitivity_source = "macie"
        e2.sensitivity_score = simple_measurement(0.95, MeasurementSource.MACIE, MeasurementConfidence.EXTERNAL_ENRICHMENT)
        builder.add_events([e1, e2])
        (session,) = builder.flush()
        assert session.sensitivity_summary.value == 0.95
