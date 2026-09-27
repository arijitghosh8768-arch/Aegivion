"""Session construction tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from detection.credential_compromise.config import SessionConfig
from detection.credential_compromise.exceptions import SessionBuildError
from detection.credential_compromise.session import SessionBuilder, SessionTracker

BASE = datetime(2026, 9, 20, 9, 0, 0, tzinfo=timezone.utc)


def test_session_key_prefers_provider_session_id(make_event):
    event = make_event(session_id="arn:aws:sts::1:assumed-role/R/s")
    assert SessionBuilder.session_key(event).endswith("#arn:aws:sts::1:assumed-role/R/s")


def test_session_key_falls_back_to_access_key(make_event):
    event = make_event(access_key_id="AKIAEXAMPLE")
    assert SessionBuilder.session_key(event).endswith("#AKIAEXAMPLE")


def test_session_key_falls_back_to_context(make_event):
    event = make_event(source_ip="49.36.12.44", user_agent="Mozilla/5.0")
    key = SessionBuilder.session_key(event)
    assert "49.36.12.44" in key and "Mozilla/5.0" in key


def test_create_populates_session_from_event(make_event):
    event = make_event(privilege_change=True, source_ip="49.36.12.44")
    session = SessionBuilder().create(event)

    assert session.event_count == 1
    assert session.privilege_changes == 1
    assert session.unique_services == 1
    assert session.event_ids == [event.event_id]
    assert session.start_time == session.last_seen == event.timestamp


def test_append_updates_aggregates(make_event):
    builder = SessionBuilder()
    first = make_event(event_id="e1", timestamp=BASE)
    session = builder.create(first)

    second = make_event(
        event_id="e2",
        timestamp=BASE + timedelta(minutes=5),
        privilege_change=True,
    )
    updated = builder.append(session, second)

    assert updated.event_count == 2
    assert updated.privilege_changes == 1
    assert updated.event_ids == ["e1", "e2"]
    assert updated.last_seen == second.timestamp


def test_append_rejects_out_of_order_event(make_event):
    builder = SessionBuilder()
    session = builder.create(make_event(timestamp=BASE))
    older = make_event(event_id="e-old", timestamp=BASE - timedelta(minutes=1))
    with pytest.raises(SessionBuildError):
        builder.append(session, older)


def test_idle_timeout_starts_a_new_session():
    tracker = SessionTracker(SessionConfig(idle_timeout_minutes=30))
    first = _event(tracker, event_id="e1", offset_minutes=0)
    assert first.is_new_session is True
    assert first.break_reason == "no_open_session"

    second = _event(tracker, event_id="e2", offset_minutes=5)
    assert second.is_new_session is False

    third = _event(tracker, event_id="e3", offset_minutes=90)
    assert third.is_new_session is True
    assert third.break_reason == "idle_timeout"
    assert third.closed_session is not None
    assert third.closed_session.event_count == 2


def test_context_change_starts_a_new_session(make_event):
    tracker = SessionTracker()
    _event(tracker, event_id="e1", offset_minutes=0)

    decision = tracker.add_event(
        make_event(
            event_id="e2",
            timestamp=BASE + timedelta(minutes=2),
            source_ip="203.0.113.77",
        )
    )
    assert decision.is_new_session is True
    assert decision.break_reason == "context_change:source_ip"


def test_context_break_can_be_disabled(make_event):
    tracker = SessionTracker(SessionConfig(break_on_context_change=False))
    _event(tracker, event_id="e1", offset_minutes=0)
    decision = tracker.add_event(
        make_event(
            event_id="e2",
            timestamp=BASE + timedelta(minutes=2),
            source_ip="203.0.113.77",
        )
    )
    assert decision.is_new_session is False


def test_unique_services_are_counted(make_event):
    tracker = SessionTracker()
    _event(tracker, event_id="e1", offset_minutes=0, service_name="iam")
    decision = tracker.add_event(
        make_event(
            event_id="e2",
            timestamp=BASE + timedelta(minutes=1),
            service_name="s3",
        )
    )
    assert decision.session.unique_services == 2
    assert decision.is_new_session is False


def test_tracker_exposes_and_closes_open_sessions():
    tracker = SessionTracker()
    _event(tracker, event_id="e1", offset_minutes=0)
    assert len(tracker.open_sessions()) == 1
    closed = tracker.close(
        "aws:123456789012:human_user:arn:aws:iam::123456789012:user/aniruddha"
    )
    assert closed is not None
    assert tracker.open_sessions() == []


def _event(tracker: SessionTracker, *, event_id: str, offset_minutes: int, **overrides):
    from detection.credential_compromise.schemas import (
        BaselineCategory,
        EventCategory,
        IdentityActivityEvent,
        IdentityKind,
        PrincipalType,
    )

    payload = {
        "event_id": event_id,
        "timestamp": BASE + timedelta(minutes=offset_minutes),
        "principal_id": "arn:aws:iam::123456789012:user/aniruddha",
        "principal_name": "aniruddha",
        "principal_type": PrincipalType.IAM_USER,
        "identity_kind": IdentityKind.HUMAN,
        "baseline_category": BaselineCategory.HUMAN_USER,
        "identity_key": "aws:123456789012:human_user:arn:aws:iam::123456789012:user/aniruddha",
        "event_source": "iam.amazonaws.com",
        "event_name": "GetUser",
        "event_category": EventCategory.MANAGEMENT,
        "service_name": "iam",
        "source_ip": "49.36.12.44",
        "user_agent": "Mozilla/5.0",
    }
    payload.update(overrides)
    return tracker.add_event(IdentityActivityEvent(**payload))
