"""Tests for behavioral baseline aggregation and poisoning protection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from algo.detection.credential_compromise.baseline import (
    build_profile,
    hour_key,
    ip_range_key,
    merge_peer_profiles,
    select_effective_baseline,
    update_policy,
    update_profile,
    weekday_key,
)
from algo.detection.credential_compromise.config import BaselineConfig
from algo.detection.credential_compromise.profile import BaselineSelection, initial_profile
from algo.detection.credential_compromise.schemas import (
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
START = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)


def make_event(
    seq: int,
    *,
    hour: int = 10,
    weekday_offset: int = 0,
    country: str = "IN",
    ip: str = "10.20.30.40",
    asn: int = 9829,
    ua: str = "aws-cli/2.13.0",
    service: str = "s3",
    family: str = ApiFamilies.S3_DATA_READ,
    access: AccessType = AccessType.READ,
    privilege: bool = False,
    mfa: bool | None = True,
    role_arn: str | None = None,
) -> IdentityActivityEvent:
    ts = START + timedelta(days=weekday_offset, hours=hour - START.hour)
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
        role_arn=role_arn,
    )


@pytest.fixture
def profile():
    return initial_profile(
        identity_key=IDENTITY,
        principal_id="arn:aws:iam::123456789012:user/aniruddha",
        window_days=30,
        principal_name="aniruddha",
        account_id="123456789012",
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
    )


def test_hour_and_weekday_keys_are_utc_based():
    event = make_event(1, hour=23)
    assert hour_key(event) == "23"
    assert weekday_key(event) == "Mon"  # 2026-06-01 is a Monday


def test_ip_range_key_buckets_by_24():
    event = make_event(1, ip="203.0.113.77")
    assert ip_range_key(event) == "203.0.113.0/24"
    assert ip_range_key(make_event(2, ip=None)) == "unknown"


def test_build_profile_populates_distributions(profile):
    events = [
        make_event(i, hour=9 + (i % 3), weekday_offset=i % 5, service="s3")
        for i in range(60)
    ]
    built = build_profile(profile, events, config=BaselineConfig())

    assert built.event_count == 60
    assert built.baseline_quality is not BaselineQuality.COLD_START
    assert sum(built.normal_hours.values()) == pytest.approx(1.0)
    assert sum(built.normal_services.values()) == pytest.approx(1.0)
    assert built.normal_services["s3"] == pytest.approx(1.0)
    assert built.normal_countries["IN"] == pytest.approx(1.0)
    assert "09" in built.normal_hours and "11" in built.normal_hours
    assert built.observation_start is not None and built.observation_end is not None


def test_build_profile_rejects_empty_events(profile):
    with pytest.raises(ValueError):
        build_profile(profile, [], config=BaselineConfig())


def test_build_profile_privilege_level_escalates(profile):
    events = [make_event(i, privilege=(i < 8), family=ApiFamilies.IAM_PRIVILEGE_MUTATION) for i in range(10)]
    built = build_profile(profile, events, config=BaselineConfig())
    assert built.normal_privilege_level in ("MODERATE", "ELEVATED")


def test_update_policy_bands():
    config = BaselineConfig()
    assert update_policy(event_risk=10.0, config=config) == ("eligible", 1.0)
    assert update_policy(event_risk=40.0, config=config) == (
        "limited_influence",
        config.limited_influence_factor,
    )
    assert update_policy(event_risk=70.0, config=config) == ("excluded", 0.0)
    assert update_policy(event_risk=99.0, config=config) == ("excluded", 0.0)


def test_high_risk_event_never_changes_baseline(profile):
    built = build_profile(
        profile,
        [make_event(i) for i in range(60)],
        config=BaselineConfig(),
    )
    before = built.model_copy()

    attacker_event = make_event(
        999,
        hour=3,
        country="KP",
        ip="45.12.98.7",
        asn=131279,
        ua="python-requests/2.31",
        service="iam",
        family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
        access=AccessType.WRITE,
        privilege=True,
        mfa=False,
    )
    updated = update_profile(before, attacker_event, event_risk=85.0, config=BaselineConfig())

    assert updated.baseline_version == before.baseline_version
    for field in (
        "normal_hours",
        "normal_countries",
        "normal_asns",
        "normal_ip_ranges",
        "normal_user_agents",
        "normal_services",
        "normal_api_families",
    ):
        assert getattr(updated, field) == getattr(before, field), field


def test_low_risk_event_blends_with_alpha(profile):
    config = BaselineConfig()
    built = build_profile(profile, [make_event(i) for i in range(60)], config=config)
    before_countries = dict(built.normal_countries)

    updated = update_profile(built, make_event(991, country="US"), event_risk=5.0, config=config)

    assert updated.baseline_version == built.baseline_version + 1
    alpha = config.personal_update_alpha
    assert updated.normal_countries["US"] == pytest.approx(alpha, abs=1e-6)
    assert updated.normal_countries["IN"] == pytest.approx(
        (1.0 - alpha) * before_countries["IN"], abs=1e-6
    )
    assert sum(updated.normal_countries.values()) == pytest.approx(1.0, abs=1e-6)


def test_limited_influence_event_moves_baseline_less(profile):
    config = BaselineConfig()
    built = build_profile(profile, [make_event(i) for i in range(60)], config=config)

    full = update_profile(built, make_event(991, country="US"), event_risk=5.0, config=config)
    limited = update_profile(built, make_event(991, country="US"), event_risk=50.0, config=config)

    assert limited.normal_countries["US"] < full.normal_countries["US"]
    assert limited.baseline_version == built.baseline_version + 1


def test_excluded_event_does_not_downgrade_quality(profile):
    config = BaselineConfig()
    events = [make_event(i, weekday_offset=i % 30) for i in range(200)]
    built = build_profile(profile, events, config=config)
    frozen = update_profile(built, make_event(999, hour=3), event_risk=95.0, config=config)
    assert frozen.baseline_quality == built.baseline_quality


def test_merge_peer_profiles_weights_by_event_count():
    peers = []
    for idx, (country, count) in enumerate((("US", 300), ("DE", 100))):
        base = initial_profile(
            identity_key=f"peer-{idx}",
            principal_id=f"peer-{idx}",
            window_days=30,
            baseline_category=BaselineCategory.HUMAN_USER,
        )
        events = [make_event(i, country=country) for i in range(count)]
        peers.append(build_profile(base, events, config=BaselineConfig()))

    merged = merge_peer_profiles(peers, window_days=30)
    assert merged is not None
    assert merged.event_count == 400
    assert merged.normal_countries["US"] == pytest.approx(0.75, abs=1e-6)
    assert merged.normal_countries["DE"] == pytest.approx(0.25, abs=1e-6)
    assert merged.baseline_quality is BaselineQuality.COLD_START


def test_select_effective_baseline_prefers_personal(profile):
    config = BaselineConfig()
    # Spread over days so the profile grades LIMITED (not COLD_START) and the
    # personal baseline is actually usable.
    personal = build_profile(
        profile,
        [make_event(i, weekday_offset=i % 5) for i in range(60)],
        config=config,
    )
    assert personal.baseline_quality is not BaselineQuality.COLD_START
    selection = BaselineSelection(
        identity_key=IDENTITY,
        window_days=30,
        quality=personal.baseline_quality,
        profile=personal,
        peer_profiles=[],
        peer_count=0,
        reason="personal_baseline",
    )
    effective, reason = select_effective_baseline(selection, config=config)
    assert reason == "personal_baseline"
    assert effective is personal


def test_select_effective_baseline_falls_back_to_peers(profile):
    selection = BaselineSelection(
        identity_key=IDENTITY,
        window_days=30,
        quality=BaselineQuality.COLD_START,
        profile=None,
        peer_profiles=[
            build_profile(
                initial_profile(
                    identity_key=f"peer-{i}",
                    principal_id=f"peer-{i}",
                    window_days=30,
                    baseline_category=BaselineCategory.HUMAN_USER,
                ),
                [make_event(i * 100 + j) for j in range(30)],
                config=BaselineConfig(),
            )
            for i in range(3)
        ],
        peer_count=3,
        reason="no_personal_baseline_with_peer_fallback",
    )
    effective, reason = select_effective_baseline(selection, config=BaselineConfig())
    assert reason.startswith("peer_baseline:")
    assert effective is not None
    assert sum(effective.normal_hours.values()) == pytest.approx(1.0)


def test_select_effective_baseline_abstains_without_peers():
    selection = BaselineSelection(
        identity_key=IDENTITY,
        window_days=30,
        quality=BaselineQuality.COLD_START,
        profile=None,
        peer_profiles=[],
        peer_count=0,
        reason="no_personal_baseline",
    )
    effective, reason = select_effective_baseline(selection, config=BaselineConfig())
    assert effective is None
    assert reason == "no_usable_baseline"
