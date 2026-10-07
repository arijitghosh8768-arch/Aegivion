"""Schema tests: canonical event, taxonomy, profile, session invariants."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from detection.cloud_destruction.exceptions import MalformedEventError
from detection.cloud_destruction.schemas import (
    ActionCategory,
    BusinessCriticality,
    DESTRUCTIVE_CATEGORIES,
    DestructiveActivitySession,
    OperationType,
    RECOVERY_IMPAIRING_CATEGORIES,
    ResourceActivityEvent,
    ResourceProtectionProfile,
    ResourceType,
    ensure_utc,
    map_resource_type,
)

from detection.cloud_destruction.tests.helpers import make_event


class TestActionTaxonomy:
    def test_all_spec_categories_exist(self):
        expected = {
            "create", "read", "modify", "rewrite", "delete", "version_delete",
            "snapshot_delete", "backup_delete", "recovery_point_delete",
            "protection_change", "restore", "share_change", "policy_change",
        }
        assert {c.value for c in ActionCategory} >= expected

    def test_destructive_set_contains_recovery_impairing(self):
        assert RECOVERY_IMPAIRING_CATEGORIES <= DESTRUCTIVE_CATEGORIES

    def test_destructive_property(self):
        event = make_event(action_category=ActionCategory.SNAPSHOT_DELETE)
        assert event.is_destructive
        assert event.is_recovery_impairing
        benign = make_event(action_category=ActionCategory.READ)
        assert not benign.is_destructive


class TestResourceActivityEvent:
    def test_minimal_event_round_trip(self):
        event = make_event()
        dumped = event.model_dump()
        assert ResourceActivityEvent.model_validate(dumped) == event

    def test_naive_timestamp_coerced_to_utc(self):
        naive = datetime(2026, 9, 10, 12, 0, 0)
        event = make_event(timestamp=naive)
        assert event.timestamp.tzinfo is timezone.utc

    def test_empty_event_id_rejected(self):
        with pytest.raises(MalformedEventError):
            make_event(event_id="   ")

    def test_negative_counts_rejected(self):
        with pytest.raises(MalformedEventError):
            make_event(object_count=-1)
        with pytest.raises(MalformedEventError):
            make_event(bytes_changed=-5)

    def test_invalid_action_string_rejected(self):
        with pytest.raises(MalformedEventError):
            make_event(action="totally-made-up-action")

    def test_action_backfilled_from_category(self):
        event = make_event(action="unknown", action_category=ActionCategory.VERSION_DELETE)
        assert event.action == "version_delete"

    def test_extra_fields_forbidden(self):
        with pytest.raises(Exception):
            make_event(some_invented_field="nope")

    def test_log_dict_has_no_request_parameters(self):
        event = make_event(request_parameters={"password": "super-secret"})
        log = event.to_log_dict()
        assert "request_parameters" not in log
        assert "password" not in str(log)


class TestResourceProtectionProfile:
    def test_recoverability_score_defaults_to_none(self):
        profile = ResourceProtectionProfile(resource_id="bkt")
        assert profile.recoverability_score is None
        assert not profile.has_protection

    def test_has_protection_variants(self):
        profile = ResourceProtectionProfile(resource_id="bkt", backup_enabled=True)
        assert profile.has_protection
        locked = ResourceProtectionProfile(
            resource_id="bkt", versioning_enabled=True, object_lock_enabled=True
        )
        assert locked.has_protection
        version_only = ResourceProtectionProfile(resource_id="bkt", versioning_enabled=True)
        assert not version_only.has_protection

    def test_criticality_enum_accepted(self):
        profile = ResourceProtectionProfile(
            resource_id="bkt", business_criticality=BusinessCriticality.CRITICAL
        )
        assert profile.business_criticality is BusinessCriticality.CRITICAL


class TestDestructiveSession:
    def test_defaults_are_zeroed(self):
        session = DestructiveActivitySession(session_id="s-1", actor_id="a")
        assert session.event_count == 0
        assert session.destructive_event_count == 0
        assert session.unique_resource_count == 0
        assert session.risk_state == "new"

    def test_duration_seconds(self):
        start = datetime.now(timezone.utc)
        session = DestructiveActivitySession(
            session_id="s-1", start_time=start, end_time=start + timedelta(seconds=90)
        )
        assert session.duration_seconds == 90.0


class TestMapResourceType:
    def test_s3_bucket_vs_object(self):
        assert map_resource_type("arn:aws:s3:::my-bucket") is ResourceType.S3_BUCKET
        assert map_resource_type("arn:aws:s3:::my-bucket/key.txt") is ResourceType.S3_OBJECT

    def test_snapshots(self):
        assert map_resource_type("arn:aws:ec2:us-east-1:1:snapshot/snap-1") is ResourceType.EBS_SNAPSHOT
        assert map_resource_type("arn:aws:rds:us-east-1:1:snapshot:snap-1") is ResourceType.RDS_SNAPSHOT

    def test_backup_and_recovery_points(self):
        assert map_resource_type("arn:aws:backup:us-east-1:1:backup-vault:v") is ResourceType.BACKUP_VAULT
        assert (
            map_resource_type("arn:aws:backup:us-east-1:1:backup-vault:v/recovery-point/rp")
            is ResourceType.RECOVERY_POINT
        )

    def test_unknown_stays_unknown(self):
        assert map_resource_type(None) is ResourceType.UNKNOWN
        assert map_resource_type("gibberish") is ResourceType.UNKNOWN
