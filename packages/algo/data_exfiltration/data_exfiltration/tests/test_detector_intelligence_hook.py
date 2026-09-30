"""Detector + behavioral intelligence integration (optional hook)."""

from __future__ import annotations

from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector
from algo.data_exfiltration.data_exfiltration.intelligence import (
    BehavioralProfiler,
    IntelligenceContext,
    KnownUniverse,
)

from .fixtures.scenarios import scenario_normal_s3_access


def test_detector_without_profiler_unchanged() -> None:
    """Part 1 behavior is untouched when no profiler is supplied."""
    detector = DataExfiltrationDetector()
    result = detector.process_events(cloudtrail_records=scenario_normal_s3_access())
    assert result.behavioral_features == []
    assert result.profile_results == []
    assert len(result.findings) == 1


def test_detector_with_profiler_emits_features() -> None:
    profiler = BehavioralProfiler()
    context = IntelligenceContext(known_destinations=KnownUniverse(destinations={"198.18.0.1"}))
    detector = DataExfiltrationDetector(profiler=profiler, intelligence_context=context)
    result = detector.process_events(cloudtrail_records=scenario_normal_s3_access())

    assert len(result.behavioral_features) == len(result.sessions) == 1
    fset = result.behavioral_features[0]
    assert fset.session_id == result.sessions[0].session_id
    # Part 1 findings unchanged: no risk appears just because profiling ran
    assert result.findings[0].risk_score is None
    # feature maps finalized
    assert set(fset.feature_availability) >= {"volume_score", "destination_score", "egress_score"}
    # cold start: honest unavailability, not suspicion
    assert fset.cold_start is True
    assert fset.volume_score.availability.value == "unavailable"


def test_profiler_features_survive_model_dump() -> None:
    """Feature sets must serialize for Threat Correlation / Part 3."""
    profiler = BehavioralProfiler()
    detector = DataExfiltrationDetector(profiler=profiler)
    result = detector.process_events(cloudtrail_records=scenario_normal_s3_access())
    payload = result.behavioral_features[0].model_dump(mode="json")
    assert payload["subject_id"]
    assert payload["feature_provenance"]["volume_score"] == "none"
