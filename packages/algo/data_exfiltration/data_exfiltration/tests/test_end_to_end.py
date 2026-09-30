"""End-to-end pipeline tests over the ten required scenarios."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from algo.data_exfiltration.data_exfiltration.config import DetectorConfig
from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector
from algo.data_exfiltration.data_exfiltration.measurement import MeasurementConfidence, MeasurementSource
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.session import SessionBuilder
from algo.data_exfiltration.data_exfiltration.schemas import ValuePresence

from .fixtures import scenarios as sc

_BASE = datetime(2024, 11, 14, 6, 0, tzinfo=timezone.utc)


def _run(records, flows=None, config=None):
    detector = DataExfiltrationDetector(config=config)
    return detector.process_events(cloudtrail_records=records, vpc_flow_records=flows or [])


# 1 ---------------------------------------------------------------------------
def test_scenario_1_normal_s3_access() -> None:
    result = _run(sc.scenario_normal_s3_access())
    assert result.stats.events_normalized == 4
    assert result.stats.events_malformed == 0
    assert len(result.sessions) == 1
    session = result.sessions[0]
    assert session.event_count == 4
    assert session.resources_accessed == ["s3://app-assets"]
    # small estimated bytes, no flows -> egress explicitly unavailable
    assert session.bytes_accessed.value == 100_000.0
    assert session.network_egress_bytes is None
    assert result.findings[0].arde["volumes"]["network_egress_bytes"]["presence"] == "unavailable"


# 2 ---------------------------------------------------------------------------
def test_scenario_2_legit_backup() -> None:
    result = _run(sc.scenario_legit_backup())
    assert len(result.sessions) == 1
    session = result.sessions[0]
    assert session.event_count == 6
    assert session.bytes_accessed.value == 3_000_000_000.0
    assert "arn:aws:sts::111122223333:assumed-role/BackupOperator" in session.actor_id
    # backup UA recorded in profile workloads
    profile = next(p for p in result.resource_profiles if p.resource_id == "s3://backups-prod")
    assert any("backup-agent" in w for w in profile.known_workloads)


# 3 ---------------------------------------------------------------------------
def test_scenario_3_sensitive_access() -> None:
    macie_table = {"prod-customer-data": {"classification": "PERSONAL_INFORMATION", "score": 0.9}}
    from algo.data_exfiltration.data_exfiltration.enrichment import StaticMacieEnricher

    detector = DataExfiltrationDetector(
        config=DetectorConfig(),
        analyzers=None,
        macie_enricher=None,
    )
    # enrichment happens through ResourceProfileBuilder in this pipeline,
    # so assert via profile path
    events = [EventNormalizer().normalize_cloudtrail(r) for r in sc.scenario_sensitive_access()]
    from algo.data_exfiltration.data_exfiltration.resource_profile import ResourceProfileBuilder

    builder = ResourceProfileBuilder(macie_enricher=StaticMacieEnricher(macie_table))
    builder.observe(events)
    profile = builder.build("s3://prod-customer-data")
    assert profile.sensitivity_level.value == "pii"
    assert profile.sensitivity_score.value == 0.9


# 4 ---------------------------------------------------------------------------
def test_scenario_4_unknown_destination() -> None:
    result = _run(sc.scenario_unknown_destination())
    assert len(result.sessions) == 1
    session = result.sessions[0]
    assert session.event_count == 1
    # copy is BOTH read+write with bytes measured
    assert session.bytes_accessed.value == 3_000_000
    detector_analyses = result.findings[0].metadata["analyses"]
    assert "destination" in detector_analyses
    assert "volume" in detector_analyses


# 5 ---------------------------------------------------------------------------
def test_scenario_5_abnormal_enumeration() -> None:
    result = _run(sc.scenario_abnormal_enumeration())
    assert len(result.sessions) == 1
    session = result.sessions[0]
    assert session.enumerate_list_count == 30
    assert session.event_count == 30
    analyses = result.findings[0].metadata["analyses"]
    assert analyses["access_pattern"]["signals"]["enumerate_list_ratio"] == 1.0


# 6 ---------------------------------------------------------------------------
def test_scenario_6_large_network_egress() -> None:
    records, flow_dicts = sc.scenario_large_network_egress(flow_reader=None)
    result = _run(records, flow_dicts)
    assert result.stats.flows_normalized == 5
    assert result.stats.sessions_with_flow_evidence == 1
    session = result.sessions[0]
    egress = session.network_egress_bytes
    assert egress is not None
    flow_contrib = [m for m in egress.measurements if m.source is MeasurementSource.VPC_FLOW_LOG]
    assert flow_contrib, "flow contribution missing"
    assert flow_contrib[0].confidence is MeasurementConfidence.OBSERVED
    assert flow_contrib[0].value == 410_000_000  # 5 x 82MB summed
    # estimated cloudtrail bytes kept in a SEPARATE channel
    ct_contrib = [m for m in session.bytes_accessed.measurements if m.source is MeasurementSource.CLOUDTRAIL]
    assert ct_contrib and ct_contrib[0].confidence is MeasurementConfidence.ESTIMATED
    assert "198.51.100.77" in session.unique_destinations


# 7 ---------------------------------------------------------------------------
def test_scenario_7_slow_movement() -> None:
    # 45-minute gaps -> widen the inactivity gap; also raise the duration
    # cap because the trickle legitimately spans >8h
    from algo.data_exfiltration.data_exfiltration.config import SessionConfig

    result = _run(
        sc.scenario_slow_movement(),
        config=DetectorConfig(session=SessionConfig(inactivity_gap=3600, max_session_duration=12 * 3600)),
    )
    assert len(result.sessions) == 1
    session = result.sessions[0]
    assert session.event_count == 12
    duration_h = (session.end_time_epoch_ms - session.start_time_epoch_ms) / 3_600_000.0
    assert duration_h >= 8.0
    analyses = result.findings[0].metadata["analyses"]
    assert analyses["volume"]["signals"]["bytes_per_second"] is not None


# 8 ---------------------------------------------------------------------------
def test_scenario_8_malformed_event() -> None:
    result = _run(sc.scenario_malformed_event())
    assert result.stats.events_in == 2
    assert result.stats.events_malformed == 2
    assert result.stats.events_normalized == 0
    assert result.findings == []
    assert len(result.stats.errors) == 2


# 9 ---------------------------------------------------------------------------
def test_scenario_9_incomplete_telemetry() -> None:
    result = _run(sc.scenario_incomplete_telemetry())
    assert result.stats.events_normalized == 4
    assert result.stats.events_malformed == 0
    session = result.sessions[0]
    assert session.bytes_accessed is None  # none of the events measured bytes
    arde = result.findings[0].arde
    assert arde["volumes"]["bytes_accessed"]["presence"] == "unavailable"


# 10 --------------------------------------------------------------------------
def test_scenario_10_mixed_missing_destination() -> None:
    records, flow_dicts = sc.scenario_mixed_missing_destination(flow_reader=None)
    result = _run(records, flow_dicts)
    assert result.stats.events_normalized == 6
    assert result.stats.flows_normalized == 3
    session = result.sessions[0]
    # destination known from flows for the covered subset
    assert "198.51.100.77" in session.unique_destinations
    egress = session.network_egress_bytes
    assert egress is not None
    assert [m for m in egress.measurements if m.source is MeasurementSource.VPC_FLOW_LOG]
    # data-event bytes channel: only estimated contributions
    assert all(
        m.confidence is MeasurementConfidence.ESTIMATED
        for m in session.bytes_accessed.measurements
        if m.source is MeasurementSource.CLOUDTRAIL
    )


# ---------------------------------------------------------------------------
# persistence round-trip
# ---------------------------------------------------------------------------

def test_end_to_end_persistence(tmp_path=None) -> None:
    from algo.data_exfiltration.data_exfiltration.storage import DetectionRepository

    repo = DetectionRepository("sqlite:///:memory:")
    detector = DataExfiltrationDetector(repository=repo)
    result = detector.process_events(cloudtrail_records=sc.scenario_normal_s3_access())
    assert repo.list_events()
    assert repo.list_sessions()
    assert repo.list_findings()
    profile = repo.get_resource_profile("s3://app-assets")
    assert profile is not None and profile.history_event_count == 4
