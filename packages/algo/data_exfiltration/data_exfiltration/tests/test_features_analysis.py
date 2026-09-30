"""Feature extraction + analysis module tests (signals only, no risk)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from algo.data_exfiltration.data_exfiltration.access_pattern import AccessPatternAnalyzer
from algo.data_exfiltration.data_exfiltration.destination import DestinationAnalyzer
from algo.data_exfiltration.data_exfiltration.features import extract_features, feature_vector
from algo.data_exfiltration.data_exfiltration.measurement import MeasurementConfidence, MeasurementSource
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.sensitivity import SensitivityAnalyzer
from algo.data_exfiltration.data_exfiltration.session import SessionBuilder
from algo.data_exfiltration.data_exfiltration.volume import VolumeAnalyzer

from .fixtures.cloudtrail_records import S3_GET, S3_LIST


def _get(iso: str, out: int | None = 1024) -> dict:
    rec = {**S3_GET, "eventTime": iso, "requestParameters": {"bucketName": "b", "key": "k"}}
    if out is None:
        rec["additionalEventData"] = None
    else:
        rec["additionalEventData"] = {"bytesTransferredOut": out}
    return rec


def _one_session(records: list[dict]):
    events = [EventNormalizer().normalize_cloudtrail(r) for r in records]
    builder = SessionBuilder()
    builder.add_events(events)
    (session,) = builder.flush()
    return session


class TestFeatures:
    def test_features_are_documented(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z"), _get("2024-11-14T03:01:00Z")])
        features = extract_features(session)
        assert features.duration_seconds == 60.0
        assert features.bytes_total == 2048
        assert features.bytes_per_second is not None
        assert "bytes_total" in features.descriptions
        assert "bytes_per_second" in features.descriptions

    def test_feature_vector_numeric_only(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z")])
        vec = feature_vector(extract_features(session))
        assert set(vec) >= {"duration_seconds", "bytes_total", "egress_bytes"}
        assert vec["egress_bytes"] is None

    def test_missing_bytes_feature_is_none(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z", out=None)])
        features = extract_features(session)
        assert features.bytes_total is None
        assert features.bytes_total_provenance is None


class TestVolumeAnalyzer:
    def test_volume_signals(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z", out=500), _get("2024-11-14T03:00:30Z", out=700)])
        result = VolumeAnalyzer().run(session)
        assert result.risk_score is None  # Part 1 never scores
        assert result.signals["bytes_total"] == 1200
        assert result.signals["bytes_presence"] == "estimated"
        assert result.signals["network_egress_presence"] == "unavailable"

    def test_volume_with_flow_evidence(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z")])
        session = session.model_copy(update={
            "network_egress_bytes": __import__(
                "algo.data_exfiltration.data_exfiltration.measurement", fromlist=["simple_measurement"]
            ).simple_measurement(5_000_000, MeasurementSource.VPC_FLOW_LOG, MeasurementConfidence.OBSERVED),
        })
        result = VolumeAnalyzer().run(session)
        assert result.signals["network_egress_bytes"] == 5_000_000
        assert result.signals["network_egress_presence"] == "observed"


class TestDestinationAnalyzer:
    def test_unknown_universe_is_explicit(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z")])
        session = session.model_copy(update={"unique_destinations": ["198.51.100.7"]})
        result = DestinationAnalyzer().run(session)
        assert result.signals["known_destination_universe"] == "not supplied"
        assert result.signals["unrecognized_destinations"] is None
        assert result.signals["destination_classification"]["198.51.100.7"] == "public"

    def test_known_universe_flags_unrecognized(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z")])
        session = session.model_copy(update={"unique_destinations": ["198.51.100.7", "10.0.0.5"]})
        analyzer = DestinationAnalyzer(known_destinations={"10.0.0.5"})
        result = analyzer.run(session)
        assert result.signals["unrecognized_destinations"] == ["198.51.100.7"]
        assert result.signals["destination_classification"]["10.0.0.5"] == "private"


class TestAccessPatternAnalyzer:
    def test_unexpected_actor_flagged_as_evidence(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z")])
        analyzer = AccessPatternAnalyzer(expected_consumers={"somebody-else"})
        result = analyzer.run(session)
        assert result.signals["actor_familiarity"] == "unexpected"

    def test_familiarity_not_supplied(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z")])
        result = AccessPatternAnalyzer().run(session)
        assert result.signals["actor_familiarity"] == "not supplied"

    def test_enumeration_signals(self) -> None:
        records = []
        for i in range(4):
            rec = {**S3_LIST, "eventTime": f"2024-11-14T03:0{i}:00Z"}
            records.append(rec)
        session = _one_session(records)
        result = AccessPatternAnalyzer().run(session)
        assert result.signals["enumerate_list_count"] == 4
        assert result.signals["enumerate_list_ratio"] == 1.0


class TestSensitivityAnalyzer:
    def test_unavailable_when_no_enrichment(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z")])
        result = SensitivityAnalyzer().run(session)
        assert result.signals["sensitivity_presence"] == "unavailable"
        assert "enrichment" in result.signals["sensitivity_unavailable_reason"]

    def test_available_with_enrichment(self) -> None:
        session = _one_session([_get("2024-11-14T03:00:00Z")])
        from algo.data_exfiltration.data_exfiltration.measurement import OptionalMeasurements, simple_measurement

        session = session.model_copy(update={
            "sensitivity_summary": OptionalMeasurements(
                measurement=simple_measurement(0.9, MeasurementSource.MACIE, MeasurementConfidence.EXTERNAL_ENRICHMENT),
            ),
        })
        result = SensitivityAnalyzer().run(session)
        assert result.signals["sensitivity_presence"] == "available"
        assert result.signals["max_sensitivity_score"] == 0.9
