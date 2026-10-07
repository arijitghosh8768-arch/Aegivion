"""Session builder tests: grouping, splitting, counters."""

from __future__ import annotations

from datetime import timedelta

from detection.cloud_destruction.config import SessionConfig
from detection.cloud_destruction.schemas import (
    ActionCategory,
    OperationType,
    ResourceType,
)
from detection.cloud_destruction.session import DestructiveSessionBuilder

from detection.cloud_destruction.tests.helpers import advance, make_event


class TestGrouping:
    def test_events_from_one_actor_group_into_one_session(self):
        events = [
            make_event(event_id=f"e{i}", timestamp=advance(make_event().timestamp, i * 60))
            for i in range(5)
        ]
        sessions = DestructiveSessionBuilder().build_sessions(events)
        assert len(sessions) == 1
        session = sessions[0]
        assert session.event_count == 5
        assert session.destructive_event_count == 5
        assert session.actor_id == "alice.admin"

    def test_idle_gap_splits_sessions(self):
        base = make_event().timestamp
        events = [
            make_event(event_id="e1", timestamp=base),
            make_event(event_id="e2", timestamp=base + timedelta(minutes=5)),
            # 40-minute gap: beyond the default 30-minute idle timeout
            make_event(event_id="e3", timestamp=base + timedelta(minutes=45)),
        ]
        sessions = DestructiveSessionBuilder().build_sessions(events)
        assert len(sessions) == 2
        assert [s.event_count for s in sessions] == [2, 1]

    def test_max_duration_force_split(self):
        config = SessionConfig(idle_timeout_minutes=60, max_duration_hours=1)
        base = make_event().timestamp
        events = [
            make_event(event_id=f"e{i}", timestamp=base + timedelta(minutes=25 * i))
            for i in range(4)  # spans 75 minutes -> two sessions
        ]
        sessions = DestructiveSessionBuilder(config).build_sessions(events)
        assert len(sessions) == 2

    def test_different_actors_split(self):
        base = make_event().timestamp
        events = [
            make_event(event_id="a1", timestamp=base, actor_id="alice"),
            make_event(event_id="b1", timestamp=base, actor_id="bob"),
        ]
        sessions = DestructiveSessionBuilder().build_sessions(events)
        assert {s.actor_id for s in sessions} == {"alice", "bob"}

    def test_missing_actor_groups_separately(self):
        base = make_event().timestamp
        events = [
            make_event(event_id="a1", timestamp=base),
            make_event(event_id="anon", timestamp=base, actor_id=None),
        ]
        sessions = DestructiveSessionBuilder().build_sessions(events)
        assert len(sessions) == 2
        assert any(s.actor_id is None for s in sessions)

    def test_account_change_splits_when_keyed(self):
        base = make_event().timestamp
        events = [
            make_event(event_id="a1", timestamp=base, account_id="111122223333"),
            make_event(event_id="a2", timestamp=base + timedelta(minutes=1), account_id="444455556666"),
        ]
        assert len(DestructiveSessionBuilder().build_sessions(events)) == 2
        config = SessionConfig(key_by_account=False)
        assert len(DestructiveSessionBuilder(config).build_sessions(events)) == 1

    def test_input_order_does_not_matter(self):
        base = make_event().timestamp
        events = [
            make_event(event_id="late", timestamp=base + timedelta(minutes=10)),
            make_event(event_id="early", timestamp=base),
        ]
        sessions = DestructiveSessionBuilder().build_sessions(events)
        assert sessions[0].event_ids == ["early", "late"]
        assert sessions[0].start_time < sessions[0].end_time


class TestCounters:
    def test_category_counters(self):
        base = make_event().timestamp
        events = [
            make_event(event_id="mod", timestamp=base, action_category=ActionCategory.MODIFY,
                       resource_arn="arn:aws:s3:::b/k1"),
            make_event(event_id="rw", timestamp=base, action_category=ActionCategory.REWRITE,
                       resource_arn="arn:aws:s3:::b/k2"),
            make_event(event_id="vd", timestamp=base, action_category=ActionCategory.VERSION_DELETE,
                       operation_type=OperationType.VERSIONED, resource_arn="arn:aws:s3:::b/k3"),
            make_event(event_id="dm", timestamp=base, action_category=ActionCategory.VERSION_DELETE,
                       is_delete_marker=True, resource_arn="arn:aws:s3:::b/k4"),
            make_event(event_id="snap", timestamp=base, action_category=ActionCategory.SNAPSHOT_DELETE,
                       resource_type=ResourceType.EBS_SNAPSHOT,
                       resource_arn="arn:aws:ec2:us-east-1:1:snapshot/snap-1"),
            make_event(event_id="rp", timestamp=base, action_category=ActionCategory.RECOVERY_POINT_DELETE,
                       resource_type=ResourceType.RECOVERY_POINT,
                       resource_arn="arn:aws:backup:us-east-1:1:backup-vault:v/recovery-point/rp"),
            make_event(event_id="prot", timestamp=base, action_category=ActionCategory.PROTECTION_CHANGE,
                       resource_arn="arn:aws:s3:::b"),
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        assert session.destructive_event_count == 7
        assert session.version_deletions == 2
        assert session.delete_marker_count == 1
        assert session.snapshot_deletions == 1
        assert session.backup_deletions == 1  # recovery point deletions count here
        assert session.protection_changes == 1
        assert session.rewrite_count == 1
        assert session.unique_resource_count == 7

    def test_read_events_not_destructive(self):
        base = make_event().timestamp
        events = [
            make_event(event_id="r1", timestamp=base, action_category=ActionCategory.READ),
            make_event(event_id="c1", timestamp=base, action_category=ActionCategory.CREATE),
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        assert session.destructive_event_count == 0
        assert session.deleted_resources == []
        assert session.modified_resources == []

    def test_critical_resource_flagged(self):
        from detection.cloud_destruction.schemas import BusinessCriticality

        event = make_event(business_criticality=BusinessCriticality.CRITICAL)
        session = DestructiveSessionBuilder().build_sessions([event])[0]
        assert session.critical_resource_touched

    def test_restore_counted_separately(self):
        event = make_event(action_category=ActionCategory.RESTORE)
        session = DestructiveSessionBuilder().build_sessions([event])[0]
        assert session.restore_count == 1
        assert session.destructive_event_count == 0

    def test_modified_and_deleted_disjoint(self):
        base = make_event().timestamp
        events = [
            make_event(event_id="d1", timestamp=base, resource_arn="arn:aws:s3:::b/k1"),
            make_event(event_id="m1", timestamp=base, action_category=ActionCategory.MODIFY,
                       resource_arn="arn:aws:s3:::b/k2"),
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        assert session.deleted_resources == ["arn:aws:s3:::b/k1"]
        assert session.modified_resources == ["arn:aws:s3:::b/k2"]
