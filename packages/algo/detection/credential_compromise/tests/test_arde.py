"""ARDE validator unit tests - ten checks, robustness score, status bands."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from algo.detection.credential_compromise.arde import ArdeInput, validate_finding
from algo.detection.credential_compromise.config import ArdeConfig
from algo.detection.credential_compromise.exceptions import ConfigurationError
from algo.detection.credential_compromise.features import BehavioralFeatures, FeatureValue
from algo.detection.credential_compromise.schemas import (
    BaselineCategory,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    IdentitySession,
    PrincipalType,
)

START = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
IDENTITY = "aws:111122223333:user:arde-test"


def make_event(seq: int = 1, **overrides) -> IdentityActivityEvent:
    payload = dict(
        event_id=f"arde-{seq:04d}",
        timestamp=START,
        ingest_time=START,
        principal_id=IDENTITY,
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
        identity_key=IDENTITY,
        event_source="iam.amazonaws.com",
        event_name="PutUserPolicy",
        event_category=EventCategory.MANAGEMENT,
        service_name="iam",
        api_family="IAM_PRIVILEGE_MUTATION",
        read_or_write="write",
        privilege_change=True,
        source_ip="10.20.30.40",
        country="IN",
        asn=9829,
        user_agent="aws-cli/2.13.0",
        mfa_authenticated=True,
    )
    payload.update(overrides)
    return IdentityActivityEvent(**payload)


def make_features(**values: float) -> BehavioralFeatures:
    defaults = {name: 0.9 for name in (
        "time_anomaly", "country_novelty", "region_novelty", "location_anomaly",
        "ip_novelty", "asn_novelty", "network_reputation", "network_anomaly",
        "client_novelty", "device_anomaly", "api_novelty", "service_novelty",
        "api_frequency_deviation", "read_write_deviation", "api_sequence_deviation",
        "api_anomaly", "privilege_anomaly",
    )}
    defaults.update(values)

    def fv(name: str) -> FeatureValue:
        return FeatureValue(
            name=name,
            value=defaults[name],
            confidence=0.0 if defaults[name] == 0.0 else 0.9,
        )

    return BehavioralFeatures(
        time_anomaly=fv("time_anomaly"),
        country_novelty=fv("country_novelty"),
        region_novelty=fv("region_novelty"),
        location_anomaly=fv("location_anomaly"),
        ip_novelty=fv("ip_novelty"),
        asn_novelty=fv("asn_novelty"),
        network_reputation=fv("network_reputation"),
        network_anomaly=fv("network_anomaly"),
        client_novelty=fv("client_novelty"),
        device_anomaly=fv("device_anomaly"),
        api_novelty=fv("api_novelty"),
        service_novelty=fv("service_novelty"),
        api_frequency_deviation=fv("api_frequency_deviation"),
        read_write_deviation=fv("read_write_deviation"),
        api_sequence_deviation=fv("api_sequence_deviation"),
        api_anomaly=fv("api_anomaly"),
        privilege_anomaly=fv("privilege_anomaly"),
    )


def make_input(**overrides) -> ArdeInput:
    bundle = dict(
        event=make_event(),
        features=make_features(),
        signals=({"rule_id": "R010", "signal": "privilege_modification", "severity": "HIGH", "value": 1.0},),
        rule_score=0.6,
        event_risk=85.0,
    )
    bundle.update(overrides)
    return ArdeInput(**bundle)


def test_clean_bundle_passes_all_ten_checks():
    result = validate_finding(make_input(), config=ArdeConfig())
    assert result.robustness_score == 100.0
    assert result.validation_status == "PASSED"
    assert len(result.checks) == 10
    assert not result.failed_checks()


def test_status_bands_ordering():
    config = ArdeConfig()
    assert config.status_rejected_below < config.status_review_below < config.status_warnings_below
    with pytest.raises(ConfigurationError):
        ArdeConfig(status_rejected_below=90, status_review_below=50, status_warnings_below=70)


def test_incomplete_evidence_deducts_points():
    event = make_event(source_ip=None, country=None)
    result = validate_finding(make_input(event=event), config=ArdeConfig())
    check = next(c for c in result.checks if c.check_id == "C02")
    assert not check.passed
    assert check.penalty == ArdeConfig().penalty_incomplete_evidence
    assert result.robustness_score == 100.0 - check.penalty
    assert result.validation_status == "PASSED_WITH_WARNINGS"


def test_rule_ml_disagreement_sets_needs_review_not_forced_risk():
    bundle = make_input(rule_score=0.9, anomaly_score=0.05, anomaly_model_used=True)
    result = validate_finding(bundle, config=ArdeConfig())
    check = next(c for c in result.checks if c.check_id == "C05")
    assert not check.passed
    assert check.needs_review is True
    assert result.needs_review is True
    assert any("disagree" in note for note in result.notes)
    # Disagreement lowers robustness but must not REJECT on its own.
    assert result.validation_status in ("PASSED_WITH_WARNINGS", "REVIEW_REQUIRED")


def test_baseline_poisoning_flagged_when_high_risk_event_folded():
    bundle = make_input(baseline_updated_by_event=True, event_risk=85.0, baseline_freeze_threshold=70.0)
    result = validate_finding(bundle, config=ArdeConfig())
    check = next(c for c in result.checks if c.check_id == "C08")
    assert not check.passed
    assert check.needs_review is True
    assert any("folded_into_baseline" in issue for issue in check.evidence["issues"])


def test_input_integrity_catches_timestamp_skew():
    event = make_event(ingest_time=START + timedelta(hours=100))
    result = validate_finding(make_input(event=event), config=ArdeConfig())
    check = next(c for c in result.checks if c.check_id == "C09")
    assert not check.passed
    assert check.penalty == ArdeConfig().penalty_input_integrity
    assert result.validation_status == "REVIEW_REQUIRED"


def test_impossible_feature_combination_detected():
    # All dimensions at absolute maximum simultaneously is incoherent.
    names = (
        "time_anomaly", "country_novelty", "region_novelty", "location_anomaly",
        "ip_novelty", "asn_novelty", "network_reputation", "network_anomaly",
        "client_novelty", "device_anomaly", "api_novelty", "service_novelty",
        "api_frequency_deviation", "read_write_deviation", "api_sequence_deviation",
        "api_anomaly", "privilege_anomaly",
    )
    maxed = make_features(**{name: 1.0 for name in names})
    result = validate_finding(make_input(features=maxed), config=ArdeConfig())
    check = next(c for c in result.checks if c.check_id == "C01")
    assert "all_dimensions_maxed" in check.evidence["violations"]


def test_temporal_and_session_checks_use_session_data():
    session = IdentitySession(
        session_key="k",
        identity_key=IDENTITY,
        principal_id=IDENTITY,
        start_time=START - timedelta(hours=30),
        last_seen=START + timedelta(hours=1),
        event_count=5,
        event_ids=["arde-0001"],
    )
    result = validate_finding(make_input(session=session), config=ArdeConfig())
    session_check = next(c for c in result.checks if c.check_id == "C07")
    temporal_check = next(c for c in result.checks if c.check_id == "C06")
    assert not session_check.passed  # 31h session exceeds the 24h policy bound
    assert temporal_check.passed  # event itself sits inside the session window


def test_rejected_status_requires_severe_penalties():
    config = ArdeConfig()
    penalties = (
        config.penalty_input_integrity
        + config.penalty_incomplete_evidence
        + config.penalty_baseline_contamination
        + config.penalty_rule_ml_disagreement
        + config.penalty_baseline_disagreement
        + config.penalty_session_inconsistency
        + config.penalty_temporal_inconsistency
        + config.penalty_model_uncertainty
    )
    assert penalties >= config.status_rejected_below


def test_result_is_deterministic():
    bundle = make_input()
    first = validate_finding(bundle, config=ArdeConfig())
    second = validate_finding(bundle, config=ArdeConfig())
    assert first.to_dict() == second.to_dict()


def test_arde_input_rejects_out_of_range_scores():
    with pytest.raises(ValidationError):
        make_input(rule_score=1.5)
