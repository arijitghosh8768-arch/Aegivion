"""Repository tests against an in-memory database."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from algo.detection.credential_compromise.profile import PeerCriteria
from algo.detection.credential_compromise.schemas import (
    BaselineCategory,
    BaselineQuality,
    CloudProvider,
    IdentityKind,
    IdentitySession,
    PrincipalType,
    Severity,
)
from algo.storage.finding_repository import FindingRecord, SqlFindingRepository
from algo.storage.event_repository import SqlEventRepository
from algo.storage.identity_repository import SqlIdentityProfileRepository
from algo.storage.models import BaselineVersionRow

NOW = datetime(2026, 9, 20, 9, 0, tzinfo=timezone.utc)


def _profile(
    identity_key: str,
    *,
    window_days: int = 30,
    account_id: str = "123456789012",
    baseline_category: BaselineCategory = BaselineCategory.HUMAN_USER,
    baseline_quality: BaselineQuality = BaselineQuality.GOOD,
    event_count: int = 600,
    department: str = "platform",
    principal_type: PrincipalType = PrincipalType.IAM_USER,
    identity_kind: IdentityKind = IdentityKind.HUMAN,
):
    from algo.detection.credential_compromise.schemas import IdentityProfile

    return IdentityProfile(
        identity_key=identity_key,
        provider=CloudProvider.AWS,
        account_id=account_id,
        principal_id=identity_key.rsplit(":", 1)[-1],
        principal_name="aniruddha",
        principal_type=principal_type,
        identity_kind=identity_kind,
        baseline_category=baseline_category,
        window_days=window_days,
        event_count=event_count,
        distinct_days=12,
        department=department,
        baseline_quality=baseline_quality,
        normal_hours={"9": 0.4, "10": 0.6},
        normal_api_families={"IAM_READ": 0.8, "S3_DATA_READ": 0.2},
    )


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #


def test_profile_roundtrip(db_session):
    repository = SqlIdentityProfileRepository(db_session)
    stored = repository.upsert_profile(_profile("aws:1:human_user:alice"))

    fetched = repository.get_profile("aws:1:human_user:alice", 30)
    assert fetched is not None
    assert fetched.principal_name == "aniruddha"
    assert fetched.baseline_quality is BaselineQuality.GOOD
    assert fetched.normal_api_families == {"IAM_READ": 0.8, "S3_DATA_READ": 0.2}
    assert fetched.baseline_category is BaselineCategory.HUMAN_USER
    assert stored.baseline_version == 1


def test_profile_upsert_increments_version(db_session):
    repository = SqlIdentityProfileRepository(db_session)
    repository.upsert_profile(_profile("aws:1:human_user:alice", event_count=600))
    updated = repository.upsert_profile(_profile("aws:1:human_user:alice", event_count=900))

    assert updated.baseline_version == 2
    fetched = repository.get_profile("aws:1:human_user:alice", 30)
    assert fetched is not None
    assert fetched.event_count == 900


def test_profiles_are_keyed_per_window(db_session):
    repository = SqlIdentityProfileRepository(db_session)
    repository.upsert_profile(_profile("aws:1:human_user:alice", window_days=7))
    repository.upsert_profile(_profile("aws:1:human_user:alice", window_days=30))

    assert repository.get_profile("aws:1:human_user:alice", 7) is not None
    assert repository.get_profile("aws:1:human_user:alice", 90) is None
    assert len(repository.list_profiles()) == 2


def test_find_peers_excludes_cold_start_and_other_categories(db_session):
    repository = SqlIdentityProfileRepository(db_session)
    repository.upsert_profile(_profile("aws:1:human_user:peer-good"))
    repository.upsert_profile(
        _profile("aws:1:human_user:peer-cold", baseline_quality=BaselineQuality.COLD_START)
    )
    repository.upsert_profile(
        _profile(
            "aws:1:service_identity:svc",
            baseline_category=BaselineCategory.SERVICE_IDENTITY,
            principal_type=PrincipalType.AWS_SERVICE,
            identity_kind=IdentityKind.SERVICE,
        )
    )
    repository.upsert_profile(
        _profile("aws:1:human_user:other-dept", department="finance")
    )

    criteria = PeerCriteria(
        baseline_category=BaselineCategory.HUMAN_USER,
        account_id="123456789012",
        department="platform",
    )
    peers = repository.find_peer_profiles(
        criteria=criteria, window_days=30, exclude_identity_key="aws:1:human_user:target"
    )

    assert [peer.identity_key for peer in peers] == ["aws:1:human_user:peer-good"]


def test_peer_lookup_can_exclude_an_identity(db_session):
    repository = SqlIdentityProfileRepository(db_session)
    repository.upsert_profile(_profile("aws:1:human_user:alice"))
    criteria = PeerCriteria(
        baseline_category=BaselineCategory.HUMAN_USER,
        account_id="123456789012",
        department="platform",
    )
    peers = repository.find_peer_profiles(
        criteria=criteria, window_days=30, exclude_identity_key="aws:1:human_user:alice"
    )
    assert peers == []


def test_baseline_versions_are_snapshotted_and_rotated(db_session):
    repository = SqlIdentityProfileRepository(db_session)
    profile = repository.upsert_profile(_profile("aws:1:human_user:alice"))

    repository.record_baseline_version(profile, span_days=20.0)
    profile = repository.upsert_profile(_profile("aws:1:human_user:alice", event_count=900))
    repository.record_baseline_version(profile, span_days=25.0)

    active = repository.get_active_baseline_version("aws:1:human_user:alice", 30)
    assert active is not None
    assert active.version == 2
    assert active.span_days == 25.0

    rows = db_session.execute(select(BaselineVersionRow)).scalars().all()
    assert len(rows) == 2
    assert sum(1 for row in rows if row.is_active) == 1


def test_delete_profile(db_session):
    repository = SqlIdentityProfileRepository(db_session)
    repository.upsert_profile(_profile("aws:1:human_user:alice"))
    assert repository.delete_profile("aws:1:human_user:alice", 30) is True
    assert repository.get_profile("aws:1:human_user:alice", 30) is None
    assert repository.delete_profile("aws:1:human_user:alice", 30) is False


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #


def test_events_never_persist_credential_material(db_session, make_event):
    repository = SqlEventRepository(db_session, secret_salt="test-salt")
    row = repository.save_event(make_event(access_key_id="AKIAEXAMPLEDEVKEY"))

    assert row.access_key_fingerprint is not None
    assert "AKIAEXAMPLEDEVKEY" not in row.access_key_fingerprint
    assert len(row.access_key_fingerprint) == 64
    assert row.access_key_masked is not None
    assert row.access_key_masked.startswith("AKIA")
    assert "EXAMPLE" not in row.access_key_masked

    rehydrated = repository.get_event(row.event_id)
    assert rehydrated is not None
    assert rehydrated.access_key_id is None


def test_event_save_is_idempotent(db_session, make_event):
    repository = SqlEventRepository(db_session)
    first = repository.save_event(make_event(event_id="evt-1"))
    second = repository.save_event(make_event(event_id="evt-1", event_name="ListUsers"))

    assert first.id == second.id
    assert repository.count_events(
        "aws:123456789012:human_user:arn:aws:iam::123456789012:user/aniruddha"
    ) == 1


def test_recent_events_are_ordered_and_scoped(db_session, make_event):
    repository = SqlEventRepository(db_session)
    identity = "aws:123456789012:human_user:user-a"
    other = "aws:123456789012:human_user:user-b"

    repository.save_event(
        make_event(event_id="e2", identity_key=identity, timestamp=NOW + timedelta(hours=2))
    )
    repository.save_event(make_event(event_id="e1", identity_key=identity, timestamp=NOW))
    repository.save_event(make_event(event_id="e3", identity_key=other, timestamp=NOW))

    events = repository.recent_events(identity)
    assert [event.event_id for event in events] == ["e1", "e2"]

    since_filtered = repository.recent_events(identity, since=NOW + timedelta(hours=1))
    assert [event.event_id for event in since_filtered] == ["e2"]


def test_attach_session_key(db_session, make_event):
    repository = SqlEventRepository(db_session)
    repository.save_event(make_event(event_id="evt-1"))
    assert repository.attach_session_key("evt-1", "session-1") is True
    assert repository.attach_session_key("missing", "session-1") is False


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #


def _session(session_key: str = "s1", event_count: int = 1) -> IdentitySession:
    return IdentitySession(
        session_key=session_key,
        identity_key="aws:123456789012:human_user:alice",
        account_id="123456789012",
        principal_id="alice",
        principal_name="alice",
        baseline_category=BaselineCategory.HUMAN_USER,
        start_time=NOW,
        last_seen=NOW + timedelta(minutes=10),
        event_count=event_count,
        unique_services=2,
        privilege_changes=1,
        api_count=event_count,
        event_ids=["e1"],
        source_ip="49.36.12.44",
    )


def test_session_roundtrip_and_upsert(db_session):
    repository = SqlEventRepository(db_session)
    repository.save_session(_session(event_count=1))

    fetched = repository.get_session("s1")
    assert fetched is not None
    assert fetched.event_count == 1
    assert fetched.privilege_changes == 1

    repository.save_session(_session(event_count=5))
    fetched = repository.get_session("s1")
    assert fetched is not None
    assert fetched.event_count == 5


def test_list_sessions(db_session):
    repository = SqlEventRepository(db_session)
    repository.save_session(_session("s1"))
    repository.save_session(_session("s2"))

    sessions = repository.list_sessions("aws:123456789012:human_user:alice")
    assert len(sessions) == 2


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _finding(finding_id: str = "f1", **overrides) -> FindingRecord:
    payload = {
        "finding_id": finding_id,
        "identity_key": "aws:123456789012:human_user:alice",
        "account_id": "123456789012",
        "principal_id": "alice",
        "principal_name": "alice",
        "severity": Severity.HIGH,
        "risk_score": 92.0,
        "confidence": 0.89,
        "signals": ["New country", "Privilege change"],
        "evidence": [{"field": "country", "normal": "IN", "observed": "DE"}],
        "recommended_actions": ["Verify activity with the account owner"],
        "session_key": "s1",
        "first_seen": NOW,
        "last_seen": NOW + timedelta(minutes=5),
    }
    payload.update(overrides)
    return FindingRecord(**payload)


def test_finding_roundtrip(db_session):
    repository = SqlFindingRepository(db_session)
    repository.save_finding(_finding())

    fetched = repository.get_finding("f1")
    assert fetched is not None
    assert fetched.severity is Severity.HIGH
    assert fetched.risk_score == pytest.approx(92.0)
    # Risk and confidence stay distinct.
    assert fetched.confidence == pytest.approx(0.89)
    assert fetched.signals == ["New country", "Privilege change"]


def test_finding_upsert_updates_in_place(db_session):
    repository = SqlFindingRepository(db_session)
    repository.save_finding(_finding())
    repository.save_finding(_finding(risk_score=95.0, severity=Severity.CRITICAL))

    findings = repository.list_findings()
    assert len(findings) == 1
    assert findings[0].risk_score == pytest.approx(95.0)
    assert findings[0].severity is Severity.CRITICAL


def test_finding_listing_and_status(db_session):
    repository = SqlFindingRepository(db_session)
    repository.save_finding(_finding("f1", risk_score=85.0))
    repository.save_finding(_finding("f2", risk_score=40.0, severity=Severity.MEDIUM))

    assert len(repository.list_findings(min_risk=60.0)) == 1
    assert repository.update_status("f1", "TRIAGED") is True
    assert repository.set_arde_status("f1", "VALIDATED") is True
    assert repository.update_status("missing", "OPEN") is False

    fetched = repository.get_finding("f1")
    assert fetched is not None
    assert fetched.status == "TRIAGED"
    assert fetched.arde_status == "VALIDATED"


def test_finding_masked_view_is_log_safe(db_session):
    view = _finding().masked_view()
    assert view["risk_score"] == 92.0
    assert view["severity"] == "HIGH"
    assert "AKIA" not in str(view)


@pytest.mark.parametrize(
    ("field", "value"),
    [("risk_score", 150.0), ("confidence", 1.5)],
)
def test_finding_bounds_are_validated(field, value):
    with pytest.raises(Exception):
        _finding(**{field: value})
