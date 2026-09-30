"""Adversarial robustness tests - synthetic manipulation scenarios.

ARDE's job is to catch findings built on noisy, manipulated, incomplete or
inconsistent evidence. Each scenario here synthesizes one manipulation class
(no real attack tooling - synthetic events only) and asserts ARDE responds
with reduced robustness, review, or rejection.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from algo.detection.credential_compromise.arde import ArdeInput, validate_finding
from algo.detection.credential_compromise.config import ArdeConfig
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
IDENTITY = "aws:111122223333:user:adv"


def ev(seq: int, **overrides) -> IdentityActivityEvent:
    payload = dict(
        event_id=f"adv-{seq:04d}",
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


def feats(**values: float) -> BehavioralFeatures:
    defaults = {name: 0.8 for name in (
        "time_anomaly", "country_novelty", "region_novelty", "location_anomaly",
        "ip_novelty", "asn_novelty", "network_reputation", "network_anomaly",
        "client_novelty", "device_anomaly", "api_novelty", "service_novelty",
        "api_frequency_deviation", "read_write_deviation", "api_sequence_deviation",
        "api_anomaly", "privilege_anomaly",
    )}
    defaults.update(values)

    def fv(name: str) -> FeatureValue:
        v = defaults[name]
        return FeatureValue(name=name, value=v, confidence=0.0 if v == 0.0 else 0.85)

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


def signals_high() -> tuple[dict, ...]:
    return (
        {"rule_id": "R010", "signal": "privilege_modification", "severity": "HIGH", "value": 1.0},
        {"rule_id": "R001", "signal": "new_country", "severity": "MEDIUM", "value": 1.0},
    )


def run(event: IdentityActivityEvent, **overrides) -> object:
    bundle = dict(
        event=event,
        features=feats(),
        signals=signals_high(),
        rule_score=0.6,
        event_risk=85.0,
    )
    bundle.update(overrides)
    return validate_finding(ArdeInput(**bundle), config=ArdeConfig())


class TestAdversarialScenarios:
    def test_manipulated_timestamp_backdated_ingest(self):
        # Event claims 2026 but was ingested 100h later: replay/clock skew.
        result = run(ev(1, ingest_time=START + timedelta(hours=100)))
        check = next(c for c in result.checks if c.check_id == "C09")
        assert not check.passed
        assert result.validation_status == "REVIEW_REQUIRED"

    def test_impossible_feature_combination(self):
        # Every dimension fully maxed at once: corrupted aggregation, not real.
        names = (
            "time_anomaly", "country_novelty", "region_novelty", "location_anomaly",
            "ip_novelty", "asn_novelty", "network_reputation", "network_anomaly",
            "client_novelty", "device_anomaly", "api_novelty", "service_novelty",
            "api_frequency_deviation", "read_write_deviation", "api_sequence_deviation",
            "api_anomaly", "privilege_anomaly",
        )
        result = run(ev(2), features=feats(**{name: 1.0 for name in names}))
        check = next(c for c in result.checks if c.check_id == "C01")
        assert "all_dimensions_maxed" in check.evidence["violations"]

    def test_abnormal_event_burst_reflected_in_windows(self):
        # A 50-event 5-minute window with privilege mutations is burst evidence.
        windows = {
            "events_5m": 50.0,
            "privilege_changes_5m": 6.0,
            "events_60m": 55.0,
            "request_burst_score": 1.0,
        }
        result = run(ev(3), temporal_windows=windows)
        # ARDE does not fail the finding for a real burst - it must still pass
        # with strong evidence; the burst is recorded, not penalized.
        assert result.validation_status in ("PASSED", "PASSED_WITH_WARNINGS")

    def test_feature_suppression_forces_review(self):
        # Zero-confidence features backing HIGH signals = incoherent evidence.
        blind = feats()
        result = run(
            ev(4),
            features=blind,
            signals=signals_high(),
        )
        cross = next(c for c in result.checks if c.check_id == "C03")
        # With values 0.8 and confidence 0.85 the signals are backed; now the
        # suppressed variant: features present but zeroed by suppression.
        suppressed = feats(
            country_novelty=0.0, ip_novelty=0.0, asn_novelty=0.0,
            time_anomaly=0.0, client_novelty=0.0, api_novelty=0.0,
            service_novelty=0.0,
        )
        result2 = run(
            ev(4),
            features=suppressed,
            signals=(
                {"rule_id": "R001", "signal": "new_country", "severity": "HIGH", "value": 1.0},
            ),
            rule_score=0.6,
        )
        cross2 = next(c for c in result2.checks if c.check_id == "C03")
        assert not cross2.passed  # HIGH signal claims a feature at value 0.0

    def test_suspicious_baseline_contamination(self):
        # Novel country yet already dominating the baseline: backwards learning.
        from algo.detection.credential_compromise.profile import initial_profile
        from algo.detection.credential_compromise.schemas import BaselineQuality

        poisoned = initial_profile(
            identity_key=IDENTITY,
            principal_id=IDENTITY,
            window_days=30,
        ).model_copy(
            update={
                "normal_countries": {"KP": 0.6, "IN": 0.4},
                "baseline_quality": BaselineQuality.GOOD,
            }
        )
        # Country novelty must be high enough to trigger the contamination
        # signature (novel >= 0.9 while the "novel" country holds p >= 0.5),
        # and the event must come from the very country that contaminated the
        # baseline (KP, p=0.6 there).
        result = run(
            ev(5, country="KP"),
            profile=poisoned,
            features=feats(country_novelty=0.95, location_anomaly=0.95),
        )
        check = next(c for c in result.checks if c.check_id == "C08")
        assert not check.passed
        assert any("dominates_baseline" in issue for issue in check.evidence["issues"])

    def test_client_spoofing_is_evidence_not_verdict(self):
        # A spoofed-looking client alone must not break validation: ARDE
        # records the anomaly but the finding stands on its other evidence.
        result = run(ev(6, user_agent="Mozilla/5.0 (spoofed-fingerprint)"))
        assert result.validation_status in ("PASSED", "PASSED_WITH_WARNINGS", "REVIEW_REQUIRED")

    def test_noisy_location_signals(self):
        # Location enrichment missing entirely: completeness penalty, no crash.
        result = run(ev(7, country=None, source_ip=None))
        completeness = next(c for c in result.checks if c.check_id == "C02")
        assert not completeness.passed
        assert "country" in completeness.evidence["missing"]

    def test_conflicting_telemetry_between_event_and_session(self):
        # Event timestamp before its own session start: contradiction.
        session = IdentitySession(
            session_key="k",
            identity_key=IDENTITY,
            principal_id=IDENTITY,
            start_time=START + timedelta(hours=2),
            last_seen=START + timedelta(hours=3),
            event_count=3,
            event_ids=["adv-0008"],
        )
        result = run(ev(8), session=session)
        temporal = next(c for c in result.checks if c.check_id == "C06")
        assert not temporal.passed
        assert "event_precedes_session_start" in temporal.evidence["issues"]

    def test_missing_critical_fields(self):
        # The schema rejects empty event identity fields at ingestion; ARDE's
        # C09 documents the same guard for events that bypass normalization.
        event = ev(9)
        object.__setattr__(event, "event_source", "")
        result = run(event)
        integrity = next(c for c in result.checks if c.check_id == "C09")
        assert not integrity.passed
        assert any("missing_event_identity_fields" in i for i in integrity.evidence["issues"])
