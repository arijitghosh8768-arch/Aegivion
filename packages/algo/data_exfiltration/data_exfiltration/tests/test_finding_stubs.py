"""Finding + ARDE + Part 2 stub interface tests."""

from __future__ import annotations

import pytest

from algo.data_exfiltration.data_exfiltration.anomaly import NotImplementedAnomalyDetector
from algo.data_exfiltration.data_exfiltration.base import AnalysisResult, PassthroughAnalyzer
from algo.data_exfiltration.data_exfiltration.confidence import NotImplementedConfidenceCalibrator
from algo.data_exfiltration.data_exfiltration.finding import build_discovery_finding
from algo.data_exfiltration.data_exfiltration.scorer import NotImplementedRiskScorer
from algo.data_exfiltration.data_exfiltration.schemas import FindingType, Provider

from .fixtures.cloudtrail_records import S3_GET


def _session():
    from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
    from algo.data_exfiltration.data_exfiltration.session import SessionBuilder

    event = EventNormalizer().normalize_cloudtrail(S3_GET)
    builder = SessionBuilder()
    builder.add_events([event])
    (session,) = builder.flush()
    return session


class TestDiscoveryFinding:
    def test_no_risk_no_severity_no_confidence(self) -> None:
        finding = build_discovery_finding(_session(), [PassthroughAnalyzer().run(_session())])
        assert finding.risk_score is None
        assert finding.severity is None
        assert finding.confidence is None
        assert finding.finding_type is FindingType.DATA_DISCOVERY
        assert "No risk score" in finding.description

    def test_arde_payload_is_evidence_complete(self) -> None:
        finding = build_discovery_finding(_session(), [])
        arde = finding.arde
        assert arde["arde_version"] == "1.0"
        for block in ("session", "resources", "volumes", "network", "sensitivity", "event_references"):
            assert block in arde
        # bytes were measured (estimated) -> present with provenance
        assert arde["volumes"]["bytes_accessed"]["presence"] == "estimated"
        # no flows were correlated -> explicit unavailability
        assert arde["volumes"]["network_egress_bytes"]["presence"] == "unavailable"
        assert arde["sensitivity"]["presence"] == "unavailable"

    def test_analysis_signals_embedded(self) -> None:
        session = _session()
        result = AnalysisResult(analysis_name="demo", signals={"k": 1})
        finding = build_discovery_finding(session, [result])
        assert finding.metadata["analyses"]["demo"]["signals"]["k"] == 1


class TestPart2Stubs:
    def test_anomaly_stub_raises(self) -> None:
        detector = NotImplementedAnomalyDetector()
        with pytest.raises(NotImplementedError):
            detector.fit([])
        with pytest.raises(NotImplementedError):
            detector.score(None)

    def test_scorer_stub_raises(self) -> None:
        with pytest.raises(NotImplementedError):
            NotImplementedRiskScorer().score(_session(), [])

    def test_confidence_stub_raises(self) -> None:
        finding = build_discovery_finding(_session(), [])
        with pytest.raises(NotImplementedError):
            NotImplementedConfidenceCalibrator().calibrate(finding)


class TestDetectorIndependence:
    """Algorithm #2 must not import or call Algorithm #1."""

    def test_no_credential_compromise_dependency(self) -> None:
        import algo.data_exfiltration.data_exfiltration as pkg
        import pathlib

        root = pathlib.Path(pkg.__file__).parent
        forbidden = ("credential_" + "compromise", "identity_" + "compromise")
        offenders = []
        for path in root.rglob("*.py"):
            if "tests" in path.parts:
                continue  # this test names the tokens; skip test sources
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                if token in text:
                    offenders.append((path.name, token))
        assert offenders == []
