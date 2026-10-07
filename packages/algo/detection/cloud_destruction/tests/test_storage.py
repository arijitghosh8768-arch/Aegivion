"""Storage layer tests: event/session/profile round trips."""

from __future__ import annotations

import json

from algo.detection.cloud_destruction.storage import (
    DestructionRepository,
    ResourceActivityEventRow,
)

from algo.detection.cloud_destruction.tests.helpers import make_event


class TestEventStorage:
    def test_save_and_list_events(self):
        repo = DestructionRepository()
        events = [make_event(event_id=f"e{i}") for i in range(3)]
        assert repo.save_events(events) == 3
        loaded = repo.list_events()
        assert len(loaded) == 3
        assert {e.event_id for e in loaded} == {"e0", "e1", "e2"}

    def test_event_round_trip_preserves_canonical_payload(self):
        repo = DestructionRepository()
        event = make_event(
            event_id="full-1",
            object_count=4,
            bytes_changed=None,
            request_parameters={"bucketName": "b", "key": "k"},
        )
        repo.save_events([event])
        loaded = repo.get_event("full-1")
        assert loaded == event
        assert loaded.request_parameters == {"bucketName": "b", "key": "k"}

    def test_json_payload_is_serializable_and_compact(self):
        event = make_event(event_id="json-1")
        payload = json.loads(event.model_dump_json())
        assert payload["event_id"] == "json-1"
        assert "timestamp" in payload

    def test_count_events(self):
        repo = DestructionRepository()
        assert repo.count_events() == 0
        repo.save_events([make_event(event_id="c1"), make_event(event_id="c2")])
        assert repo.count_events() == 2

    def test_get_missing_event_returns_none(self):
        repo = DestructionRepository()
        assert repo.get_event("nope") is None


class TestSessionStorage:
    def test_session_round_trip(self):
        repo = DestructionRepository()
        from algo.detection.cloud_destruction.session import DestructiveSessionBuilder

        events = [make_event(event_id=f"s{i}") for i in range(3)]
        sessions = DestructiveSessionBuilder().build_sessions(events)
        repo.save_events(events)
        repo.save_sessions(sessions)
        loaded = repo.list_sessions()
        assert len(loaded) == 1
        assert loaded[0].event_count == 3
        assert loaded[0].destructive_event_count == 3
        assert loaded[0].session_id == sessions[0].session_id
        assert repo.get_session(sessions[0].session_id) is not None


class TestProfileStorage:
    def test_profile_round_trip(self):
        repo = DestructionRepository()
        from algo.detection.cloud_destruction.resource_profile import ResourceProfileBuilder

        profiles = ResourceProfileBuilder().build_profiles(
            [make_event(event_id="p1", resource_id="fin-prod-archive")]
        )
        repo.save_resource_profiles(list(profiles.values()))
        loaded = repo.get_resource_profile("fin-prod-archive")
        assert loaded is not None
        assert loaded.resource_id == "fin-prod-archive"
        assert loaded.history_event_count == 1


class TestSchemaBootstrap:
    def test_create_all_is_idempotent(self):
        repo = DestructionRepository()
        # constructing again over the same URL must not fail
        repo2 = DestructionRepository()
        assert repo2 is not repo
        # table registry contains the reserved findings table
        assert "destruction_findings" in ResourceActivityEventRow.metadata.tables
