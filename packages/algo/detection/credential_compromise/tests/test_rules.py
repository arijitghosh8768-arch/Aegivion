"""Tests for the configurable rule engine (R001-R014)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from algo.detection.credential_compromise.baseline import build_profile
from algo.detection.credential_compromise.config import BaselineConfig, FeatureConfig, RuleEngineConfig
from algo.detection.credential_compromise.features import extract_features
from algo.detection.credential_compromise.profile import initial_profile
from algo.detection.credential_compromise.rules import (
    RULE_CATALOGUE,
    RuleSignal,
    evaluate_rules,
)
from algo.detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    PrincipalType,
)

IDENTITY = "aws:123456789012:human_user:arn:aws:iam::123456789012:user/aniruddha"
START = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)


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
    event_name: str = "DoThing",
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
        event_name=event_name,
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
def good_profile():
    profile = initial_profile(
        identity_key=IDENTITY,
        principal_id="arn:aws:iam::123456789012:user/aniruddha",
        window_days=30,
        account_id="123456789012",
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
    )
    events = [
        make_event(
            i,
            hour=9 + (i % 9),
            day_offset=i % 20,
            service="s3" if i % 3 else "iam",
            family=ApiFamilies.S3_DATA_READ if i % 3 else ApiFamilies.IAM_READ,
        )
        for i in range(400)
    ]
    return build_profile(profile, events, config=BaselineConfig())


def test_catalogue_ids_are_stable_and_complete():
    ids = [rule.rule_id for rule in RULE_CATALOGUE]
    assert ids == [f"R{num:03d}" for num in range(1, 15)]


def test_quiet_event_produces_no_signals(good_profile):
    features = extract_features(make_event(500), good_profile, config=BaselineConfig())
    signals = evaluate_rules(
        make_event(500), features, config=BaselineConfig(), feature_config=FeatureConfig()
    )
    assert signals == []


def test_new_country_fires_r001(good_profile):
    event = make_event(501, country="BR")
    features = extract_features(event, good_profile, config=BaselineConfig())
    signals = evaluate_rules(event, features, config=BaselineConfig())
    by_id = {signal.rule_id: signal for signal in signals}
    assert "R001" in by_id
    assert by_id["R001"].signal == "new_country"
    assert by_id["R001"].severity == "MEDIUM"


def test_new_ip_fires_r003_and_new_asn_fires_r004(good_profile):
    event = make_event(502, ip="198.51.100.7", asn=64512)
    features = extract_features(event, good_profile, config=BaselineConfig())
    signals = evaluate_rules(event, features, config=BaselineConfig())
    ids = {signal.rule_id for signal in signals}
    assert {"R003", "R004"} <= ids


def test_unusual_hour_fires_r005(good_profile):
    event = make_event(503, hour=3)
    features = extract_features(event, good_profile, config=BaselineConfig())
    signals = evaluate_rules(event, features, config=BaselineConfig())
    ids = {signal.rule_id for signal in signals}
    assert "R005" in ids


def test_new_client_fires_r006(good_profile):
    event = make_event(504, ua="python-requests/2.31")
    features = extract_features(event, good_profile, config=BaselineConfig())
    signals = evaluate_rules(event, features, config=BaselineConfig())
    ids = {signal.rule_id for signal in signals}
    assert "R006" in ids


def test_rare_api_and_service_fire_r007_r008(good_profile):
    event = make_event(505, service="organizations", family=ApiFamilies.ORGANIZATIONS_MANAGEMENT)
    features = extract_features(event, good_profile, config=BaselineConfig())
    signals = evaluate_rules(event, features, config=BaselineConfig())
    ids = {signal.rule_id for signal in signals}
    assert {"R007", "R008"} <= ids


def test_privilege_mutation_fires_r010_with_evidence(good_profile):
    event = make_event(
        506,
        service="iam",
        family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
        access=AccessType.WRITE,
        privilege=True,
    )
    features = extract_features(event, good_profile, config=BaselineConfig())
    signals = evaluate_rules(event, features, config=BaselineConfig())
    by_id = {signal.rule_id: signal for signal in signals}
    assert "R010" in by_id
    assert by_id["R010"].severity == "HIGH"
    payload = by_id["R010"].to_dict()
    assert payload["rule_id"] == "R010"
    assert payload["signal"] == "privilege_modification"
    assert payload["severity"] == "high"
    assert payload["value"] > 0
    assert "evidence" in payload


def test_access_key_operation_fires_r012(good_profile):
    event = make_event(
        507,
        service="iam",
        family=ApiFamilies.CREDENTIAL_MANAGEMENT,
        event_name="CreateAccessKey",
        access=AccessType.WRITE,
        privilege=True,
    )
    features = extract_features(event, good_profile, config=BaselineConfig())
    signals = evaluate_rules(event, features, config=BaselineConfig())
    ids = {signal.rule_id for signal in signals}
    assert "R012" in ids


def test_mfa_absent_on_privilege_change_fires_r013(good_profile):
    event = make_event(
        508,
        service="iam",
        family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
        access=AccessType.WRITE,
        privilege=True,
        mfa=False,
    )
    features = extract_features(event, good_profile, config=BaselineConfig())
    signals = evaluate_rules(event, features, config=BaselineConfig())
    by_id = {signal.rule_id: signal for signal in signals}
    assert "R013" in by_id
    assert by_id["R013"].severity == "HIGH"


def test_rules_can_be_disabled(good_profile):
    event = make_event(509, country="BR")
    features = extract_features(event, good_profile, config=BaselineConfig())
    rule_config = RuleEngineConfig(disabled_rules=("R001",))
    signals = evaluate_rules(
        event, features, config=BaselineConfig(), rule_config=rule_config
    )
    assert "R001" not in {signal.rule_id for signal in signals}


def test_rule_severity_can_be_overridden(good_profile):
    event = make_event(510, country="BR")
    features = extract_features(event, good_profile, config=BaselineConfig())
    rule_config = RuleEngineConfig(rule_severities={"R001": "HIGH"})
    signals = evaluate_rules(
        event, features, config=BaselineConfig(), rule_config=rule_config
    )
    hit = next(signal for signal in signals if signal.rule_id == "R001")
    assert hit.severity == "HIGH"


def test_rule_threshold_can_be_raised():
    """A raised threshold suppresses a rule whose evidence is merely rare.

    The fixture history covers hours 9-17 uniformly, so hour 3 there is fully
    unseen (novelty saturates at 1.0 and no threshold <= 1 can suppress it).
    Instead this test gives the identity one historical 3 AM event in 400:
    hour 3 becomes rare-but-seen, the time feature lands at ~0.92, which
    clears the default threshold (0.7) but not the raised one (0.99).
    """
    profile = initial_profile(
        identity_key=IDENTITY,
        principal_id="arn:aws:iam::123456789012:user/aniruddha",
        window_days=30,
        account_id="123456789012",
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
    )
    history = [make_event(i, hour=9 + (i % 9), day_offset=i % 20) for i in range(400)]
    history.append(make_event(600, hour=3, day_offset=21))
    trained = build_profile(profile, history, config=BaselineConfig())

    event = make_event(511, hour=3, day_offset=22)
    features = extract_features(event, trained, config=BaselineConfig())
    raw = features.time_anomaly.value
    assert 0.7 <= raw < 0.99

    default = evaluate_rules(event, features, config=BaselineConfig())
    assert "R005" in {signal.rule_id for signal in default}

    raised = evaluate_rules(
        event,
        features,
        config=BaselineConfig(),
        rule_config=RuleEngineConfig(rule_thresholds={"R005": 0.99}),
    )
    assert "R005" not in {signal.rule_id for signal in raised}


def test_cold_start_baseline_suppresses_novelty_signal_storm():
    """A brand-new identity's first event must not fire every novelty rule."""
    thin = initial_profile(
        identity_key=IDENTITY,
        principal_id="arn:aws:iam::123456789012:user/aniruddha",
        window_days=30,
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
    )
    event = make_event(
        512,
        country="KP",
        ip="45.12.98.7",
        asn=131279,
        ua="python-requests/2.31",
        service="iam",
        family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
        privilege=True,
        access=AccessType.WRITE,
    )
    features = extract_features(event, thin, config=BaselineConfig())
    feature_config = FeatureConfig(min_feature_confidence=0.3)
    signals = evaluate_rules(
        event,
        features,
        config=BaselineConfig(),
        feature_config=feature_config,
    )
    novelty_rules = {"R001", "R002", "R003", "R004", "R006", "R007", "R008"}
    assert not (novelty_rules & {signal.rule_id for signal in signals})
