"""Part 6 — False-positive context engine + exception system."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from algo.detection.cloud_destruction.context import (
    SPEC_TO_PROFILE_ACTIVITY,
    ApprovalState,
    ContextAnnotation,
    ContextEngine,
    ExceptionRecord,
    ExceptionRegistry,
    ExceptionScope,
    LegitimateActivity,
    apply_exceptions,
    spec_activity_for,
)
from algo.detection.cloud_destruction.exceptions import (
    CloudDestructionError,
)
from algo.detection.cloud_destruction.legitimate import (
    ApprovedActivityProfile,
)
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    ActorType,
)
from algo.detection.cloud_destruction.tests.helpers import (
    BASE_TIME,
    advance,
    make_event,
)


class TestExceptionRecords:
    def test_record_defaults_and_active(self):
        now = BASE_TIME
        record = ExceptionRecord(
            owner="sec-team",
            created_at=now,
            approval_state=ApprovalState.APPROVED,
        )
        assert record.is_active(now=now)
        assert record.scope is ExceptionScope.GLOBAL

    def test_record_expires(self):
        record = ExceptionRecord(
            owner="sec-team",
            created_at=BASE_TIME,
            expires_at=BASE_TIME + timedelta(hours=1),
            approval_state=ApprovalState.APPROVED,
        )
        assert record.is_active(now=BASE_TIME)
        assert not record.is_active(
            now=BASE_TIME + timedelta(hours=2))

    def test_pending_record_never_active(self):
        record = ExceptionRecord(
            owner="sec-team",
            created_at=BASE_TIME,
        )
        assert not record.is_active()

    def test_scope_matching(self):
        from algo.detection.cloud_destruction.schemas import (
            DestructiveActivitySession,
        )
        session = DestructiveActivitySession(
            session_id="s-1", actor_id="alice",
            provider="aws", account_id="acct-1",
            start_time=BASE_TIME, end_time=BASE_TIME,
            event_count=1, destructive_event_count=1,
            resources_touched=["r1"],
        )
        global_rec = ExceptionRecord(
            owner="o", created_at=BASE_TIME,
            approval_state=ApprovalState.APPROVED)
        actor_rec = ExceptionRecord(
            owner="o", created_at=BASE_TIME,
            approval_state=ApprovalState.APPROVED,
            scope=ExceptionScope.ACTOR, actor_ids=("alice",))
        wrong_actor = ExceptionRecord(
            owner="o", created_at=BASE_TIME,
            approval_state=ApprovalState.APPROVED,
            scope=ExceptionScope.ACTOR, actor_ids=("bob",))
        assert global_rec.matches(session)
        assert actor_rec.matches(session)
        assert not wrong_actor.matches(session)


class TestExceptionRegistry:
    def test_add_and_evaluate(self):
        registry = ExceptionRegistry()
        record = ExceptionRecord(
            owner="sec-team", created_at=BASE_TIME,
            approval_state=ApprovalState.APPROVED,
            reason="planned cleanup",
        )
        registry.add(record)
        assert registry.get(record.exception_id) is record

    def test_duplicate_ids_rejected(self):
        registry = ExceptionRegistry()
        record = ExceptionRecord(
            owner="sec-team", created_at=BASE_TIME)
        registry.add(record)
        with pytest.raises(CloudDestructionError):
            registry.add(record)

    def test_revoke(self):
        registry = ExceptionRegistry()
        record = ExceptionRecord(
            owner="sec-team", created_at=BASE_TIME,
            approval_state=ApprovalState.APPROVED)
        registry.add(record)
        assert registry.revoke(record.exception_id)
        updated = registry.get(record.exception_id)
        assert updated.approval_state is ApprovalState.REVOKED
        assert not updated.is_active()

    def test_evaluate_only_approved_in_scope(self):
        from algo.detection.cloud_destruction.schemas import (
            DestructiveActivitySession,
        )
        session = DestructiveActivitySession(
            session_id="s-1", actor_id="alice",
            provider="aws", account_id="acct-1",
            start_time=BASE_TIME, end_time=BASE_TIME,
            event_count=1, destructive_event_count=1,
        )
        pending = ExceptionRecord(
            owner="o", created_at=BASE_TIME)
        approved = ExceptionRecord(
            owner="o", created_at=BASE_TIME,
            approval_state=ApprovalState.APPROVED)
        registry = ExceptionRegistry([pending, approved])
        matches = registry.evaluate(session)
        assert [r.exception_id for r in matches] == [
            approved.exception_id]

    def test_activity_scoped_evaluation(self):
        from algo.detection.cloud_destruction.schemas import (
            DestructiveActivitySession,
        )
        session = DestructiveActivitySession(
            session_id="s-1", actor_id="alice",
            provider="aws", account_id="acct-1",
            start_time=BASE_TIME, end_time=BASE_TIME,
            event_count=1, destructive_event_count=1,
        )
        lifecycle = ExceptionRecord(
            owner="o", created_at=BASE_TIME,
            approval_state=ApprovalState.APPROVED,
            activity=LegitimateActivity.S3_LIFECYCLE_EXPIRATION)
        snapshot = ExceptionRecord(
            owner="o", created_at=BASE_TIME,
            approval_state=ApprovalState.APPROVED,
            activity=LegitimateActivity.SCHEDULED_SNAPSHOT_CLEANUP)
        registry = ExceptionRegistry([lifecycle, snapshot])
        # internal profile vocabulary maps to spec vocabulary
        matches = registry.evaluate(
            session, activity="lifecycle_cleanup")
        assert [r.exception_id for r in matches] == [
            lifecycle.exception_id]


class TestContextEngine:
    def test_declared_profile_annotates(self):
        profile = ApprovedActivityProfile(
            profile_id="lifecycle-1",
            activity="lifecycle_cleanup",
            justification="s3 lifecycle expiration",
            actor_ids=frozenset({"automation"}),
        )
        events = [
            make_event(event_id=f"e{i}", actor_id="automation",
                       timestamp=advance(BASE_TIME, i))
            for i in range(5)
        ]
        from algo.detection.cloud_destruction.session import (
            DestructiveSessionBuilder,
        )
        from algo.detection.cloud_destruction.config import (
            DestructionDetectorConfig,
        )
        cfg = DestructionDetectorConfig()
        sessions = DestructiveSessionBuilder(
            cfg.session).build_sessions(events)
        engine = ContextEngine(profiles=[profile])
        from algo.detection.cloud_destruction.finding import (
            DestructionFinding,
        )
        finding = DestructionFinding(
            finding_id="f", session_id=sessions[0].session_id,
            detector_name="t", severity=None, risk_score=0.0,
            confidence_score=0.0, actor_id="automation",
            account_id="a", observed_at=BASE_TIME,
            model_name="m", model_version="0",
            feature_version="0", baseline_version=None,
            scoring_version="0", rule_version="0")
        annotation = engine.evaluate(
            finding, sessions[0], events)
        assert annotation.approved_activity is not None
        assert annotation.approved_activity.approved
        assert annotation.has_context

    def test_lifecycle_pattern_recognized_from_telemetry(self):
        from algo.detection.cloud_destruction.session import (
            DestructiveSessionBuilder,
        )
        from algo.detection.cloud_destruction.config import (
            DestructionDetectorConfig,
        )
        events = [
            make_event(
                event_id=f"e{i}", timestamp=advance(BASE_TIME, i),
                raw_action="s3:DeleteObject (LifecycleExpiration)")
            for i in range(4)
        ]
        cfg = DestructionDetectorConfig()
        sessions = DestructiveSessionBuilder(
            cfg.session).build_sessions(events)
        from algo.detection.cloud_destruction.finding import (
            DestructionFinding,
        )
        finding = DestructionFinding(
            finding_id="f", session_id=sessions[0].session_id,
            detector_name="t", severity=None, risk_score=0.0,
            confidence_score=0.0, actor_id="a",
            account_id="a", observed_at=BASE_TIME,
            model_name="m", model_version="0",
            feature_version="0", baseline_version=None,
            scoring_version="0", rule_version="0")
        engine = ContextEngine()
        annotation = engine.evaluate(finding, sessions[0], events)
        activities = [h.activity for h in annotation.recognized_patterns]
        assert LegitimateActivity.S3_LIFECYCLE_EXPIRATION in activities

    def test_scheduled_snapshot_cleanup_recognized(self):
        from algo.detection.cloud_destruction.session import (
            DestructiveSessionBuilder,
        )
        from algo.detection.cloud_destruction.config import (
            DestructionDetectorConfig,
        )
        events = [
            make_event(
                event_id=f"s{i}", timestamp=advance(BASE_TIME, i),
                actor_id="backup-automation",
                actor_type=ActorType.AWS_SERVICE,
                action_category=ActionCategory.SNAPSHOT_DELETE,
                resource_id=f"snap-{i}", snapshot_id=f"snap-{i}")
            for i in range(3)
        ]
        cfg = DestructionDetectorConfig()
        sessions = DestructiveSessionBuilder(
            cfg.session).build_sessions(events)
        from algo.detection.cloud_destruction.finding import (
            DestructionFinding,
        )
        finding = DestructionFinding(
            finding_id="f", session_id=sessions[0].session_id,
            detector_name="t", severity=None, risk_score=0.0,
            confidence_score=0.0, actor_id="backup-automation",
            account_id="a", observed_at=BASE_TIME,
            model_name="m", model_version="0",
            feature_version="0", baseline_version=None,
            scoring_version="0", rule_version="0")
        annotation = ContextEngine().evaluate(
            finding, sessions[0], events)
        activities = [h.activity for h in annotation.recognized_patterns]
        assert (
            LegitimateActivity.SCHEDULED_SNAPSHOT_CLEANUP in activities)

    def test_no_context_when_nothing_matches(self):
        from algo.detection.cloud_destruction.session import (
            DestructiveSessionBuilder,
        )
        from algo.detection.cloud_destruction.config import (
            DestructionDetectorConfig,
        )
        events = [make_event(event_id="e1")]
        cfg = DestructionDetectorConfig()
        sessions = DestructiveSessionBuilder(
            cfg.session).build_sessions(events)
        from algo.detection.cloud_destruction.finding import (
            DestructionFinding,
        )
        finding = DestructionFinding(
            finding_id="f", session_id=sessions[0].session_id,
            detector_name="t", severity=None, risk_score=0.0,
            confidence_score=0.0, actor_id="a",
            account_id="a", observed_at=BASE_TIME,
            model_name="m", model_version="0",
            feature_version="0", baseline_version=None,
            scoring_version="0", rule_version="0")
        annotation = ContextEngine().evaluate(
            finding, sessions[0], events)
        assert not annotation.has_context

    def test_annotation_is_serializable(self):
        annotation = ContextAnnotation(
            finding_id="f", session_id="s")
        assert annotation.to_log_dict()["recognized_patterns"] == []


class TestApplyExceptions:
    def _finding(self):
        from algo.detection.cloud_destruction.finding import (
            DestructionFinding,
        )
        return DestructionFinding(
            finding_id="f", session_id="s", detector_name="t",
            severity=None, risk_score=0.5, confidence_score=0.5,
            actor_id="a", account_id="a", observed_at=BASE_TIME,
            model_name="m", model_version="0",
            feature_version="0", baseline_version=None,
            scoring_version="0", rule_version="0")

    def test_no_context_returns_same_finding(self):
        finding = self._finding()
        annotation = ContextAnnotation(
            finding_id="f", session_id="s")
        assert apply_exceptions(finding, annotation) is finding

    def test_context_annotates_without_softening(self):
        finding = self._finding()
        annotation = ContextAnnotation(
            finding_id="f", session_id="s",
            recognized_patterns=tuple())
        # force context via an exception record
        from algo.detection.cloud_destruction.context import (
            _PatternHit,
        )
        annotation = ContextAnnotation(
            finding_id="f", session_id="s",
            recognized_patterns=(
                _PatternHit(
                    activity=LegitimateActivity.CICD_DEPLOYMENT,
                    evidence=("all creates",)),))
        annotated = apply_exceptions(finding, annotation)
        # risk/severity untouched — annotation only
        assert annotated.risk_score == finding.risk_score
        assert annotated.severity == finding.severity
        assert annotated.finding_id == finding.finding_id
        assert "context_annotation" in annotated.raw
        assert (
            annotated.raw["context_annotation"]["recognized_patterns"]
            [0]["activity"] == "cicd_deployment")


class TestSpecVocabulary:
    def test_all_nine_activities_exist(self):
        expected = {
            "s3_lifecycle_expiration", "backup_retention_cleanup",
            "scheduled_snapshot_cleanup", "cicd_deployment",
            "database_maintenance", "resource_migration",
            "disaster_recovery_testing", "bulk_data_processing",
            "approved_infrastructure_change",
        }
        assert {a.value for a in LegitimateActivity} == expected

    def test_round_trip_mapping(self):
        # forward map: every spec activity lands in the internal vocabulary
        assert SPEC_TO_PROFILE_ACTIVITY["s3_lifecycle_expiration"] == "lifecycle_cleanup"
        assert SPEC_TO_PROFILE_ACTIVITY["backup_retention_cleanup"] == "backup_retention"
        assert SPEC_TO_PROFILE_ACTIVITY["cicd_deployment"] == "cicd_deployment"
        assert SPEC_TO_PROFILE_ACTIVITY["database_maintenance"] == "database_maintenance"
        assert SPEC_TO_PROFILE_ACTIVITY["resource_migration"] == "migration"
        assert SPEC_TO_PROFILE_ACTIVITY["bulk_data_processing"] == "batch_processing"
        # reverse map: unique internal activities map back to their spec
        assert spec_activity_for("lifecycle_cleanup") == "s3_lifecycle_expiration"
        assert spec_activity_for("backup_retention") == "backup_retention_cleanup"
        assert spec_activity_for("cicd_deployment") == "cicd_deployment"
        assert spec_activity_for("database_maintenance") == "database_maintenance"
        assert spec_activity_for("migration") == "resource_migration"
        assert spec_activity_for("batch_processing") == "bulk_data_processing"
        # shared internal activities map back to a canonical spec value
        assert spec_activity_for("scheduled_maintenance") in {
            "scheduled_snapshot_cleanup", "disaster_recovery_testing",
            "approved_infrastructure_change",
        }
        assert spec_activity_for(None) is None
        assert spec_activity_for("unknown_thing") is None
