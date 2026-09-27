"""Profile lifecycle tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

from detection.credential_compromise.config import BaselineConfig
from detection.credential_compromise.profile import (
    PeerCriteria,
    ProfileService,
    apply_observation_stats,
    assess_baseline_quality,
    initial_profile,
    observation_stats,
)
from detection.credential_compromise.schemas import (
    BaselineCategory,
    BaselineQuality,
    CloudProvider,
    IdentityKind,
    IdentityProfile,
    PrincipalType,
)

CONFIG = BaselineConfig()


def _profile(**overrides) -> IdentityProfile:
    payload = {
        "identity_key": "aws:123456789012:human_user:arn:aws:iam::123456789012:user/aniruddha",
        "provider": CloudProvider.AWS,
        "account_id": "123456789012",
        "principal_id": "arn:aws:iam::123456789012:user/aniruddha",
        "principal_name": "aniruddha",
        "principal_type": PrincipalType.IAM_USER,
        "identity_kind": IdentityKind.HUMAN,
        "baseline_category": BaselineCategory.HUMAN_USER,
        "window_days": 30,
        "department": "platform",
    }
    payload.update(overrides)
    return IdentityProfile(**payload)


# --------------------------------------------------------------------------- #
# Quality grading
# --------------------------------------------------------------------------- #


def test_too_few_events_is_cold_start():
    assert assess_baseline_quality(
        event_count=10, span_days=20, distinct_days=10, config=CONFIG
    ) is BaselineQuality.COLD_START


def test_limited_quality():
    assert assess_baseline_quality(
        event_count=60, span_days=3, distinct_days=2, config=CONFIG
    ) is BaselineQuality.LIMITED


def test_good_quality():
    assert assess_baseline_quality(
        event_count=600, span_days=20, distinct_days=10, config=CONFIG
    ) is BaselineQuality.GOOD


def test_excellent_quality():
    assert assess_baseline_quality(
        event_count=2500, span_days=40, distinct_days=35, config=CONFIG
    ) is BaselineQuality.EXCELLENT


def test_a_burst_is_not_a_baseline():
    """5,000 events in one day does not model a human's week."""
    assert assess_baseline_quality(
        event_count=5000, span_days=1, distinct_days=1, config=CONFIG
    ) is BaselineQuality.COLD_START


def test_observation_stats_measures_span_and_coverage(make_event):
    start = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)
    events = [
        make_event(event_id="a", timestamp=start),
        make_event(event_id="b", timestamp=start + timedelta(days=2)),
        make_event(event_id="c", timestamp=start + timedelta(days=2, hours=4)),
    ]
    span_days, distinct_days = observation_stats(events)
    assert span_days == 2.1666666666666665
    assert distinct_days == 2


def test_observation_stats_on_empty_input():
    assert observation_stats([]) == (0.0, 0)


# --------------------------------------------------------------------------- #
# Profile construction
# --------------------------------------------------------------------------- #


def test_initial_profile_is_honest_about_knowing_nothing():
    profile = initial_profile(
        identity_key="aws:1:human_user:u1",
        principal_id="u1",
        window_days=30,
        account_id="1",
        baseline_category=BaselineCategory.HUMAN_USER,
        principal_type=PrincipalType.IAM_USER,
    )
    assert profile.event_count == 0
    assert profile.baseline_quality is BaselineQuality.COLD_START
    assert profile.normal_hours == {}
    assert profile.normal_api_families == {}
    assert profile.baseline_version == 0


def test_apply_observation_stats_regrades_quality():
    profile = _profile()
    updated = apply_observation_stats(
        profile,
        event_count=600,
        span_days=20,
        distinct_days=10,
        config=CONFIG,
    )
    assert updated.baseline_quality is BaselineQuality.GOOD
    assert updated.event_count == 600
    assert updated.distinct_days == 10


# --------------------------------------------------------------------------- #
# Baseline selection
# --------------------------------------------------------------------------- #


class FakeProfileRepository:
    def __init__(
        self,
        personal: Optional[IdentityProfile] = None,
        peers: Optional[Sequence[IdentityProfile]] = None,
    ) -> None:
        self.personal = personal
        self.peers = list(peers or [])
        self.peer_calls: list[PeerCriteria] = []

    def get_profile(self, identity_key: str, window_days: int):
        return self.personal

    def find_peer_profiles(self, *, criteria, window_days, exclude_identity_key=None):
        self.peer_calls.append(criteria)
        return list(self.peers)


def test_personal_baseline_is_used_when_trustworthy():
    personal = _profile(baseline_quality=BaselineQuality.GOOD, event_count=600)
    service = ProfileService(FakeProfileRepository(personal))

    selection = service.select_baseline(identity_key=personal.identity_key, window_days=30)

    assert selection.is_peer_baseline is False
    assert selection.quality is BaselineQuality.GOOD
    assert selection.reason == "personal_baseline"
    assert selection.profile is personal


def test_cold_start_falls_back_to_peers():
    peers = [_profile(identity_key="peer-1"), _profile(identity_key="peer-2")]
    repository = FakeProfileRepository(personal=None, peers=peers)
    service = ProfileService(repository)

    criteria = PeerCriteria(
        baseline_category=BaselineCategory.HUMAN_USER,
        account_id="123456789012",
        department="platform",
    )
    selection = service.select_baseline(
        identity_key="aws:123456789012:human_user:new-user",
        window_days=30,
        peer_criteria=criteria,
    )

    assert selection.is_peer_baseline is True
    assert selection.peer_count == 2
    assert selection.quality is BaselineQuality.COLD_START
    assert selection.reason == "no_personal_baseline_with_peer_fallback"


def test_no_history_and_no_peers_stays_cold_start():
    service = ProfileService(FakeProfileRepository())
    selection = service.select_baseline(identity_key="unknown-identity", window_days=30)

    assert selection.is_cold_start is True
    assert selection.is_peer_baseline is False
    assert selection.peer_count == 0
    assert selection.reason == "no_personal_baseline"


def test_partial_history_derives_peer_criteria_from_the_profile():
    personal = _profile(
        baseline_quality=BaselineQuality.COLD_START,
        event_count=10,
        department="platform",
    )
    peers = [_profile(identity_key="peer-1")]
    repository = FakeProfileRepository(personal=personal, peers=peers)
    service = ProfileService(repository)

    selection = service.select_baseline(identity_key=personal.identity_key, window_days=30)

    assert selection.reason == "personal_baseline_insufficient_with_peer_fallback"
    assert repository.peer_calls[0].department == "platform"
    assert repository.peer_calls[0].baseline_category is BaselineCategory.HUMAN_USER


def test_peer_criteria_never_span_categories():
    profile = _profile(
        baseline_category=BaselineCategory.SERVICE_IDENTITY,
        principal_type=PrincipalType.AWS_SERVICE,
        identity_kind=IdentityKind.SERVICE,
    )
    criteria = ProfileService(FakeProfileRepository()).peer_criteria(profile)
    assert criteria.baseline_category is BaselineCategory.SERVICE_IDENTITY
    assert "category=service_identity" in criteria.describe()
