"""Approved-activity profile tests: scoping, time windows, reversibility,
auditability, and the no-silent-suppression rule."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from algo.data_exfiltration.data_exfiltration.arde.approved_activities import (
    APPROVED_ACTIVITY_KINDS,
    ApprovedActivityKind,
    ApprovedActivityProfile,
    ApprovedActivityRegistry,
)

_BACKUP_NIGHT = datetime(2024, 11, 14, 2, 0, tzinfo=timezone.utc)
_BACKUP_NIGHT_MS = _BACKUP_NIGHT.timestamp() * 1000.0
_BACKUP_DAY = datetime(2024, 11, 14, 14, 0, tzinfo=timezone.utc)
_BACKUP_DAY_MS = _BACKUP_DAY.timestamp() * 1000.0

_BACKUP_ACTOR = "arn:aws:sts::111122223333:assumed-role/BackupOperator/backup-job-42"
_BACKUP_BUCKET = "s3://backups-prod"


def _profile(**overrides) -> ApprovedActivityProfile:
    defaults = dict(
        profile_id="aap-backup",
        name="nightly backup",
        kind=ApprovedActivityKind.BACKUP_JOB,
        actor_patterns=["arn:aws:sts::*:assumed-role/BackupOperator/*"],
        resources=[_BACKUP_BUCKET],
        start_hour_utc=1,
        end_hour_utc=4,
        max_bytes=6 * 1024**3,
        reason="nightly production backup",
        approver="security-team",
    )
    defaults.update(overrides)
    return ApprovedActivityProfile(**defaults)


class TestRegistration:
    def test_all_eight_kinds_exist(self) -> None:
        assert set(APPROVED_ACTIVITY_KINDS) == {
            "backup_job", "data_warehouse_export", "etl_pipeline",
            "analytics_workload", "approved_migration", "scheduled_report",
            "disaster_recovery", "known_saas_transfer",
        }

    def test_unscoped_profile_rejected(self) -> None:
        with pytest.raises(ValueError, match="actor scope"):
            ApprovedActivityRegistry().register(
                _profile(actor_patterns=[], actors=[])
            )

    def test_profile_without_resource_scope_rejected(self) -> None:
        with pytest.raises(ValueError, match="resource scope"):
            ApprovedActivityRegistry().register(
                _profile(resources=[], resource_prefixes=[])
            )

    def test_register_and_revoke(self) -> None:
        registry = ApprovedActivityRegistry()
        registry.register(_profile())
        assert len(registry) == 1
        assert registry.remove("aap-backup") is True
        assert len(registry) == 0
        assert registry.remove("aap-backup") is False


class TestMatching:
    def test_backup_in_window_matches(self) -> None:
        registry = ApprovedActivityRegistry([_profile()])
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=3_000_000_000.0,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert len(records) == 1
        assert records[0].matched is True
        assert records[0].kind == "backup_job"

    def test_same_activity_outside_window_does_not_match(self) -> None:
        registry = ApprovedActivityRegistry([_profile()])
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=3_000_000_000.0,
            at_epoch_ms=_BACKUP_DAY_MS,
        )
        assert records[0].matched is False
        assert "time window" in records[0].reason

    def test_different_actor_does_not_match(self) -> None:
        registry = ApprovedActivityRegistry([_profile()])
        records = registry.evaluate(
            actor_id="arn:aws:iam::111122223333:user/mallory",
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=3_000_000_000.0,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert records[0].matched is False
        assert "actor" in records[0].reason

    def test_different_resource_does_not_match(self) -> None:
        registry = ApprovedActivityRegistry([_profile()])
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=["s3://prod-customer-data"],
            destinations=[],
            bytes_total=3_000_000_000.0,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert records[0].matched is False
        assert "resources outside" in records[0].reason

    def test_oversized_transfer_does_not_match(self) -> None:
        registry = ApprovedActivityRegistry([_profile()])
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=60_000_000_000.0,  # 60 GB >> 6 GB ceiling
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert records[0].matched is False
        assert "ceiling" in records[0].reason

    def test_destination_allowlist_enforced(self) -> None:
        profile = _profile(destinations=["10.0.0.1"])
        registry = ApprovedActivityRegistry([profile])
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=["198.51.100.77"],
            bytes_total=1_000_000.0,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert records[0].matched is False
        assert "destination" in records[0].reason


class TestTimeAwareness:
    def test_window_wrapping_midnight(self) -> None:
        profile = _profile(start_hour_utc=23, end_hour_utc=3)
        registry = ApprovedActivityRegistry([profile])
        late_night = datetime(2024, 11, 14, 1, 0, tzinfo=timezone.utc)
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=None,
            at_epoch_ms=late_night.timestamp() * 1000.0,
        )
        assert records[0].matched is True

    def test_days_of_week_respected(self) -> None:
        # 2024-11-14 is a Thursday (weekday 3); restrict to Monday only
        profile = _profile(days_of_week=frozenset({0}))
        registry = ApprovedActivityRegistry([profile])
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=None,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert records[0].matched is False
        assert "time window" in records[0].reason


class TestReversibility:
    def test_disable_stops_matching(self) -> None:
        registry = ApprovedActivityRegistry([_profile()])
        assert registry.disable("aap-backup") is True
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=None,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert records[0].matched is False
        assert "disabled" in records[0].reason
        # re-enable: reversible
        registry.enable("aap-backup")
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=None,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert records[0].matched is True

    def test_expired_profile_stops_matching(self) -> None:
        expired = _profile(expires_at_epoch_ms=_BACKUP_NIGHT_MS - 1000.0)
        registry = ApprovedActivityRegistry([expired])
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=None,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert records[0].matched is False
        assert "expired" in records[0].reason


class TestAuditability:
    def test_every_profile_yields_a_record_even_without_match(self) -> None:
        registry = ApprovedActivityRegistry(
            [_profile(), _profile(profile_id="aap-other", name="other", actor_patterns=["arn:*:user/bob"])]
        )
        records = registry.evaluate(
            actor_id="arn:aws:iam::1:user/unrelated",
            resources=["s3://somewhere"],
            destinations=[],
            bytes_total=None,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        assert len(records) == 2
        assert all(r.matched is False for r in records)
        assert all(r.profile_hash.startswith("aap-") for r in records)
        assert all(r.scope for r in records)

    def test_record_captures_scope_snapshot(self) -> None:
        registry = ApprovedActivityRegistry([_profile()])
        records = registry.evaluate(
            actor_id=_BACKUP_ACTOR,
            resources=[_BACKUP_BUCKET],
            destinations=[],
            bytes_total=None,
            at_epoch_ms=_BACKUP_NIGHT_MS,
        )
        scope = records[0].scope
        assert scope["actor_patterns"] == ["arn:aws:sts::*:assumed-role/BackupOperator/*"]
        assert scope["window_hours_utc"] == [1, 4]
        assert scope["max_bytes"] == 6 * 1024**3
