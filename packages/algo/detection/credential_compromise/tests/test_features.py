"""Tests for behavioral feature extraction (six dimensions)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from detection.credential_compromise.baseline import build_profile
from detection.credential_compromise.config import BaselineConfig, FeatureConfig, MaintenanceWindow
from detection.credential_compromise.features import (
    distribution_probability,
    extract_features,
    novelty,
)
from detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    BaselineQuality,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    PrincipalType,
)

IDENTITY = "aws:123456789012:human_user:arn:aws:iam::123456789012:user/aniruddha"
START = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)  # Monday


def make_event(
    seq: int,
    *,
    hour: int = 10,
    day_offset: int = 0,
    country: str = "IN",
    ip: str = "10.20.30.40",
    asn: int = 9829,
    ua: str = "aws-cli/2.13.0",
    service: str = "s3",
    family: str = ApiFamilies.S3_DATA_READ,
    access: AccessType = AccessType.READ,
    privilege: bool = False,
    mfa: bool | None = True,
) -> IdentityActivityEvent:
    ts = START + timedelta(days=day_offset, hours=hour - START.hour)
    return IdentityActivityEvent(
        event_id=f"evt-{seq:05d}",
        timestamp=ts,
        principal_id="arn:aws:iam::123456789012:user/aniruddha",
        principal_name="aniruddha",
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
        identity_key=IDENTITY,
        account_id="123456789012",
        event_source=f"{service}.amazonaws.com",
        event_name="DoThing",
        event_category=EventCategory.MANAGEMENT,
        service_name=service,
        api_family=family,
        read_or_write=access,
        privilege_change=privilege,
        source_ip=ip,
        country=country,
        asn=asn,
        user_agent=ua,
        mfa_authenticated=mfa,
    )


@pytest.fixture
def config():
    return BaselineConfig()


@pytest.fixture
def good_profile(config):
    base_events = [
        make_event(
            i,
            hour=9 + (i % 9),
            day_offset=i % 20,
            country="IN",
            ip="10.20.30.40",
            asn=9829,
            ua="aws-cli/2.13.0",
            service="s3",
            family=ApiFamilies.S3_DATA_READ,
        )
        for i in range(400)
    ]
    from detection.credential_compromise.profile import initial_profile

    profile = initial_profile(
        identity_key=IDENTITY,
        principal_id="arn:aws:iam::123456789012:user/aniruddha",
        window_days=30,
        account_id="123456789012",
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
    )
    return build_profile(profile, base_events, config=config)


def test_novelty_mapping():
    assert novelty(1.0, 0.03) == pytest.approx(0.03 / 1.03, abs=1e-6)
    assert novelty(0.0, 0.03) == 1.0
    assert novelty(0.03, 0.03) == pytest.approx(0.5)


def test_distribution_probability_handles_counts_and_frequencies():
    freq = {"a": 0.7, "b": 0.3}
    counts = {"a": 7.0, "b": 3.0}
    assert distribution_probability(freq, "a") == pytest.approx(0.7)
    assert distribution_probability(counts, "a") == pytest.approx(0.7)
    assert distribution_probability(freq, "zz") == 0.0
    assert distribution_probability(None, "a") == 0.0


def test_everyday_event_scores_low_everywhere(good_profile, config):
    features = extract_features(make_event(500), good_profile, config=config)
    dims = features.dimension_values()
    for dimension, value in dims.items():
        if dimension != "privilege":
            assert value < 0.3, f"{dimension}={value}"
    assert features.privilege_anomaly.value == 0.0
    assert features.time_anomaly.confidence > 0.5


def test_novel_country_ip_and_client_raise_location_and_network(good_profile, config):
    odd = make_event(
        501,
        hour=10,
        country="BR",
        ip="203.0.113.9",
        asn=64512,
        ua="python-requests/2.31",
    )
    features = extract_features(odd, good_profile, config=config)

    assert features.country_novelty.value == pytest.approx(1.0)
    assert features.ip_novelty.value == pytest.approx(1.0)
    assert features.asn_novelty.value == pytest.approx(1.0)
    assert features.client_novelty.value == pytest.approx(1.0)
    assert features.location_anomaly.value == pytest.approx(1.0)
    assert features.network_anomaly.value == pytest.approx(1.0)
    # One odd context is a signal, not a verdict: the fused dimensions stay
    # independent so the scorer can weigh corroboration.
    assert features.api_anomaly.value > 0.0
    assert features.time_anomaly.value < 0.3  # hour is normal


def test_unusual_hour_raises_time_dimension(good_profile, config):
    night = make_event(502, hour=3)
    features = extract_features(night, good_profile, config=config)
    assert features.time_anomaly.value > 0.7


def test_maintenance_window_dampens_time_anomaly(config):
    window = MaintenanceWindow(name="backup", start_hour=2, end_hour=5)
    night_config = BaselineConfig(maintenance_windows=(window,))
    from detection.credential_compromise.profile import initial_profile

    profile = build_profile(
        initial_profile(
            identity_key=IDENTITY,
            principal_id="arn:aws:iam::123456789012:user/aniruddha",
            window_days=30,
            principal_type=PrincipalType.IAM_USER,
            identity_kind=IdentityKind.HUMAN,
            baseline_category=BaselineCategory.HUMAN_USER,
        ),
        [make_event(i, hour=10, day_offset=i % 20) for i in range(300)],
        config=night_config,
    )
    night = make_event(503, hour=3)
    features = extract_features(night, profile, config=night_config)
    assert features.time_anomaly.value <= 0.3
    assert features.time_anomaly.evidence.get("maintenance_window_active") is True


def test_maintenance_window_covers_wraparound():
    window = MaintenanceWindow(name="overnight", start_hour=22, end_hour=6)
    assert window.covers(datetime(2026, 6, 1, 23, 0, tzinfo=timezone.utc)) is True
    assert window.covers(datetime(2026, 6, 2, 3, 0, tzinfo=timezone.utc)) is True
    assert window.covers(datetime(2026, 6, 2, 12, 0, tzinfo=timezone.utc)) is False


def test_corporate_range_dampens_ip_novelty(good_profile):
    corporate_config = BaselineConfig(corporate_networks=("10.20.0.0/16",))
    roaming = make_event(504, ip="10.20.99.99")
    features = extract_features(roaming, good_profile, config=corporate_config)
    assert features.ip_novelty.value == pytest.approx(1.0)
    assert features.ip_novelty.evidence["corporate_range_hit"] is True
    assert features.network_anomaly.value <= 0.6


def test_new_ip_outside_corporate_range_stays_high(good_profile):
    corporate_config = BaselineConfig(corporate_networks=("10.20.0.0/16",))
    external = make_event(505, ip="203.0.113.9")
    features = extract_features(external, good_profile, config=corporate_config)
    assert features.network_anomaly.value == pytest.approx(1.0)


def test_privilege_mutation_produces_privilege_signal(good_profile, config):
    admin_event = make_event(
        506,
        service="iam",
        family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
        access=AccessType.WRITE,
        privilege=True,
    )
    features = extract_features(admin_event, good_profile, config=config)
    assert features.privilege_anomaly.value > 0.5
    assert features.privilege_anomaly.evidence.get("iam_policy_mutation") is True


def test_admin_baseline_dampens_privilege_signal(good_profile, config):
    from detection.credential_compromise.profile import initial_profile

    admin_profile = good_profile.model_copy(update={"normal_privilege_level": "ELEVATED"})
    analyst_profile = good_profile.model_copy(update={"normal_privilege_level": "NONE"})
    event = make_event(
        507,
        service="iam",
        family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
        privilege=True,
        access=AccessType.WRITE,
    )
    admin = extract_features(event, admin_profile, config=config)
    analyst = extract_features(event, analyst_profile, config=config)
    assert admin.privilege_anomaly.value < analyst.privilege_anomaly.value


def test_write_event_deviates_for_read_only_identity(good_profile, config):
    writer = make_event(508, access=AccessType.WRITE)
    features = extract_features(writer, good_profile, config=config)
    assert features.read_write_deviation.value > 0.5


def test_no_baseline_abstains_instead_of_inventing(config):
    event = make_event(509, country="KP")
    features = extract_features(event, None, config=config)
    assert features.country_novelty.value == 0.0
    assert features.country_novelty.confidence == 0.0
    assert features.time_anomaly.confidence == 0.0
    # The one feature that never needs a baseline still fires.
    assert features.privilege_anomaly.value >= 0.0


def test_cold_start_profile_has_low_confidence(config):
    from detection.credential_compromise.profile import initial_profile

    thin = initial_profile(
        identity_key=IDENTITY,
        principal_id="arn:aws:iam::123456789012:user/aniruddha",
        window_days=30,
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
    )
    features = extract_features(make_event(510), thin, config=config)
    assert features.baseline_quality is BaselineQuality.COLD_START
    assert features.time_anomaly.confidence < 0.3


def test_evidence_dump_is_explainability_ready(good_profile, config):
    features = extract_features(
        make_event(511, service="iam", family=ApiFamilies.IAM_PRIVILEGE_MUTATION, privilege=True),
        good_profile,
        config=config,
    )
    evidence = features.to_evidence()
    assert set(evidence["dimensions"]) == {"time", "location", "ip", "device", "api", "privilege"}
    assert "time_anomaly" in evidence["features"]
    entry = evidence["features"]["country_novelty"]
    assert {"name", "value", "confidence", "observed", "expected", "evidence"} <= set(entry)
