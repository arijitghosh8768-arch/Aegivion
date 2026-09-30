"""VPC flow correlation tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from algo.data_exfiltration.data_exfiltration.config import DetectorConfig
from algo.data_exfiltration.data_exfiltration.correlate import (
    correlate_flow_events,
    enrich_session_with_flows,
    is_private_ip,
    merge_flow_evidence,
)
from algo.data_exfiltration.data_exfiltration.measurement import MeasurementConfidence, MeasurementSource
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.session import SessionBuilder

from .fixtures.cloudtrail_records import S3_GET

_BASE = datetime(2024, 11, 14, 6, 0, tzinfo=timezone.utc)


def _flow(start: datetime, src: str, dst: str, bytes_: int) -> dict:
    return {
        "version": 2,
        "interface-id": "eni-1",
        "account-id": "111122223333",
        "region": "us-east-1",
        "src-addr": src,
        "dst-addr": dst,
        "start": int(start.timestamp()),
        "end": int((start + timedelta(seconds=30)).timestamp()),
        "protocol": 6,
        "bytes": bytes_,
        "packets": 1000,
        "type": "IPv4",
    }


def _session_with_destination(dst_ip: str):
    """Build a one-event session whose destination is *dst_ip*."""
    record = {**S3_GET, "eventTime": _BASE.strftime("%Y-%m-%dT%H:%M:%SZ")}
    event = EventNormalizer().normalize_cloudtrail(record)
    event.destination_ip = dst_ip
    builder = SessionBuilder()
    builder.add_events([event])
    (session,) = builder.flush()
    return session


def _flows(*records: dict) -> list:
    nx = EventNormalizer()
    return [nx.normalize_vpc_flow(r) for r in records]


def test_private_ip_classification() -> None:
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("172.32.0.1") is False
    assert is_private_ip("198.51.100.7") is False
    assert is_private_ip(None) is None
    assert is_private_ip("not-an-ip") is False


def test_flow_matching_by_destination_ip() -> None:
    session = _session_with_destination("198.51.100.77")
    flows = _flows(_flow(_BASE + timedelta(seconds=10), "10.0.1.20", "198.51.100.77", 5_000_000))
    matched = correlate_flow_events(session, flows, DetectorConfig())
    assert len(matched) == 1


def test_flow_outside_window_not_matched() -> None:
    session = _session_with_destination("198.51.100.77")
    flows = _flows(_flow(_BASE + timedelta(minutes=30), "10.0.1.20", "198.51.100.77", 5_000_000))
    matched = correlate_flow_events(session, flows, DetectorConfig())
    assert matched == []


def test_internal_to_internal_flow_matches_without_destination() -> None:
    session = _session_with_destination(None)  # data event carries no destination
    flows = _flows(_flow(_BASE + timedelta(seconds=10), "10.0.1.20", "10.0.2.30", 2_000_000))
    matched = correlate_flow_events(session, flows, DetectorConfig())
    assert len(matched) == 1


def test_external_to_external_flow_not_matched_without_ip_link() -> None:
    session = _session_with_destination(None)
    flows = _flows(_flow(_BASE + timedelta(seconds=10), "203.0.113.9", "198.51.100.77", 2_000_000))
    matched = correlate_flow_events(session, flows, DetectorConfig())
    assert matched == []


def test_merge_adds_observed_egress() -> None:
    session = _session_with_destination("198.51.100.77")
    flows = _flows(
        _flow(_BASE + timedelta(seconds=10), "10.0.1.20", "198.51.100.77", 1_000_000),
        _flow(_BASE + timedelta(seconds=40), "10.0.1.20", "198.51.100.77", 2_000_000),
    )
    merged = merge_flow_evidence(session, flows)
    assert merged.network_egress_bytes is not None
    assert merged.network_egress_bytes.value == 3_000_000
    contribution = merged.network_egress_bytes.measurements[-1]
    assert contribution.source is MeasurementSource.VPC_FLOW_LOG
    assert contribution.confidence is MeasurementConfidence.OBSERVED
    # original session untouched (immutability)
    assert session.network_egress_bytes is None


def test_enrich_session_with_flows_end_to_end() -> None:
    session = _session_with_destination("198.51.100.77")
    flows = _flows(_flow(_BASE + timedelta(seconds=5), "10.0.1.20", "198.51.100.77", 750_000))
    enriched = enrich_session_with_flows(session, flows, DetectorConfig())
    assert enriched.network_egress_bytes.value == 750_000
    assert "198.51.100.77" in enriched.unique_destinations
