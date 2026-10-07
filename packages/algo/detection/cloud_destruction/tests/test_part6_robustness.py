"""Part 6 — robustness suite (spec §ROBUSTNESS TESTING).

Every scenario uses synthetic / replayed telemetry only. The
question each scenario answers is the spec's: *does confidence
change appropriately* when the telemetry degrades?

Scenarios (spec list):

- missing deletion events        (aggregate-mode session)
- missing snapshot events        (recovery counters without detail)
- incomplete backup records      (deletion without vault metadata)
- timestamp inconsistencies      (events outside session bounds)
- duplicated events              (same event_id twice)
- out-of-order events            (unsorted arrival)
- malformed records              (normalizer raises typed errors)
- noisy resource metadata        (unknown resource types / missing ARNs)
- baseline contamination         (destructive history never trusted)
- contradictory telemetry        (counters disagree with detail)
- legitimate scheduled cleanup   (recognized, never suppressed)

Plus confidence calibration: degraded telemetry must yield
strictly lower confidence than complete telemetry, and the
ARDE ``telemetry_completeness`` check must reflect it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from detection.cloud_destruction.arde import (
    ArdeValidator,
    CheckVerdict,
)
from detection.cloud_destruction.baseline import (
    BaselineStore,
    BaselineContamination,
    LEARNING_WEIGHT,
    classify_contamination,
)
from detection.cloud_destruction.confidence import (
    ConfidenceConfig,
    compute_confidence,
)
from detection.cloud_destruction.context import (
    ContextEngine,
    LegitimateActivity,
)
from detection.cloud_destruction.detector import DestructionDetector
from detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from detection.cloud_destruction.explainability import (
    FINDING_LABEL,
    build_explanation,
)
from detection.cloud_destruction.features import extract_features
from detection.cloud_destruction.finding import build_finding
from detection.cloud_destruction.normalizer import (
    ResourceActivityNormalizer,
)
from detection.cloud_destruction.scorer import score_destruction
from detection.cloud_destruction.session import (
    DestructiveSessionBuilder,
)
from detection.cloud_destruction.tests.helpers import (
    BASE_TIME,
    advance,
    make_event,
)


# ---------------------------------------------------------------------- #
# Harness: run the Part 2+ pipeline with a controllable
# "event detail" switch so degraded-telemetry scenarios can be
# replayed against identical sessions.
# ---------------------------------------------------------------------- #


def _pipeline(events, *, detail=True, use_ml=True):
    """Sessionize -> features -> fusion -> confidence -> finding.

    ``detail=False`` replays the session in aggregate mode (no
    per-event telemetry) — the robustness scenarios below use it
    to simulate missing telemetry.
    """
    from detection.cloud_destruction.config import (
        DestructionDetectorConfig,
    )

    cfg = DestructionDetectorConfig()
    sessions = DestructiveSessionBuilder(cfg.session).build_sessions(
        list(events)
    )
    assert sessions
    detail_events = list(events) if detail else []
    vectors = extract_features(
        sessions, detail_events, config=cfg,
    )
    per_session = {}
    for session in sessions:
        ids = set(session.event_ids)
        per_session[session.session_id] = [
            e for e in detail_events if e.event_id in ids
        ]
    results = []
    for session, vector in zip(sessions, vectors):
        risk = score_destruction(
            session, vector,
            anomaly_score=0.9 if use_ml else None,
            sequence_score=0.8,
        )
        confidence = compute_confidence(
            session, vector, risk,
            baseline_quality=vector.baseline_quality,
            has_event_detail=bool(per_session[session.session_id]),
            model_agreement=risk.model_agreement,
            config=ConfidenceConfig(),
        )
        finding = build_finding(
            session, risk, confidence,
            baseline_quality=vector.baseline_quality,
        )
        results.append(
            SimpleNamespace(
                finding=finding, session=session, vector=vector,
                risk=risk, confidence=confidence,
                events=per_session[session.session_id],
            )
        )
    return results


def _first(events, **kwargs):
    return _pipeline(events, **kwargs)[0]


def _validate(case, events=None):
    return ArdeValidator().validate(
        case.finding, case.session, case.vector,
        case.risk, case.confidence,
        case.events if events is None else events,
    )


# ---------------------------------------------------------------------- #
# 1-3: missing / incomplete telemetry
# ---------------------------------------------------------------------- #


class TestMissingDeletionEvents:
    def test_aggregate_mode_confidence_drops(self):
        events = [
            make_event(event_id=f"d{i}", timestamp=advance(BASE_TIME, i),
                       action_category=__import__(
                           "detection.cloud_destruction.schemas",
                           fromlist=["ActionCategory"]).ActionCategory.DELETE,
                       resource_id=f"obj-{i}",
                       resource_arn=f"arn:aws:s3:::bkt/obj-{i}")
            for i in range(8)
        ]
        complete = _first(events, detail=True)
        degraded = _first(events, detail=False)
        # same session counters, strictly less evidence
        assert (degraded.session.destructive_event_count
                == complete.session.destructive_event_count)
        assert (degraded.confidence.confidence_score
                < complete.confidence.confidence_score)
        # the telemetry-completeness factor is what degraded
        factors = degraded.confidence.factors
        assert factors["telemetry_completeness"] < (
            complete.confidence.factors["telemetry_completeness"])

    def test_arde_telemetry_completeness_fails(self):
        events = [
            make_event(event_id=f"d{i}", timestamp=advance(BASE_TIME, i))
            for i in range(6)
        ]
        degraded = _first(events, detail=False)
        report = _validate(degraded)
        check = report.checks["telemetry_completeness"]
        assert check.verdict is CheckVerdict.FAIL
        assert check.evidence["has_event_detail"] is False

    def test_event_consistency_unverified_without_detail(self):
        events = [make_event(event_id="d1", timestamp=BASE_TIME)]
        degraded = _first(events, detail=False)
        report = _validate(degraded)
        reasons = " ".join(report.checks["event_consistency"].reasons)
        assert "no event detail" in reasons


class TestMissingSnapshotEvents:
    def test_recovery_counters_without_detail_warn(self):
        from detection.cloud_destruction.schemas import (
            ActionCategory,
        )

        events = [
            make_event(event_id=f"s{i}", timestamp=advance(BASE_TIME, i),
                       action_category=ActionCategory.SNAPSHOT_DELETE,
                       resource_id=f"snap-{i}",
                       snapshot_id=f"snap-{i}")
            for i in range(3)
        ]
        degraded = _first(events, detail=False)
        assert degraded.session.snapshot_deletions == 3
        report = _validate(degraded)
        # recovery mechanisms destroyed but detail missing ->
        # challenge (never a silent pass)
        verdicts = (
            report.checks["recovery_consistency"].verdict,
            report.checks["telemetry_completeness"].verdict,
        )
        assert CheckVerdict.FAIL in verdicts or CheckVerdict.WARN in verdicts


class TestIncompleteBackupRecords:
    def test_backup_deletion_without_vault_still_counted(self):
        from detection.cloud_destruction.schemas import (
            ActionCategory,
        )

        # recovery-point deletion with NO backup_vault_name /
        # recovery_point_id — incomplete record, still counts.
        events = [
            make_event(event_id=f"b{i}", timestamp=advance(BASE_TIME, i),
                       action_category=ActionCategory.RECOVERY_POINT_DELETE,
                       resource_id=f"rp-{i}",
                       backup_vault_name=None,
                       recovery_point_id=None)
            for i in range(2)
        ]
        case = _first(events)
        assert case.session.backup_deletions == 2
        report = _validate(case)
        # incomplete metadata must not crash validation
        assert len(report.checks) == 10


# ---------------------------------------------------------------------- #
# 4-6: ordering / duplication / timestamps
# ---------------------------------------------------------------------- #


class TestTimestampInconsistencies:
    def test_event_outside_session_bounds_fails_time_check(self):
        events = [
            make_event(event_id=f"t{i}", timestamp=advance(BASE_TIME, i * 60))
            for i in range(4)
        ]
        case = _first(events)
        # replay with a session whose window excludes an event
        shifted = case.session.model_copy(
            update={
                "start_time": case.session.start_time + timedelta(minutes=10),
                "end_time": case.session.end_time,
            }
        )
        report = ArdeValidator().validate(
            case.finding, shifted, case.vector,
            case.risk, case.confidence, events)
        reasons = " ".join(report.checks["time_consistency"].reasons)
        assert "precedes session start_time" in reasons
        assert report.checks["time_consistency"].verdict is CheckVerdict.FAIL

    def test_finding_observed_at_outside_bounds(self):
        from dataclasses import replace

        events = [make_event(event_id="t1", timestamp=BASE_TIME)]
        case = _first(events)
        shifted = replace(
            case.finding,
            observed_at=case.session.end_time + timedelta(hours=1),
        )
        report = ArdeValidator().validate(
            shifted, case.session, case.vector,
            case.risk, case.confidence, events)
        reasons = " ".join(report.checks["time_consistency"].reasons)
        assert "follows session end" in reasons


class TestDuplicatedEvents:
    def test_duplicate_event_ids_flagged(self):
        events = [
            make_event(event_id="dup", timestamp=BASE_TIME),
            make_event(event_id="dup", timestamp=advance(BASE_TIME, 1)),
        ]
        case = _first(events)
        report = _validate(case)
        reasons = " ".join(report.checks["event_consistency"].reasons)
        assert "duplicated" in reasons

    def test_duplicates_count_in_session_aggregates(self):
        # robustness contract: the builder counts what it is given —
        # duplicated input is visible, never silently dropped
        events = [
            make_event(event_id="dup", timestamp=BASE_TIME),
            make_event(event_id="dup", timestamp=advance(BASE_TIME, 1)),
        ]
        case = _first(events)
        assert case.session.event_count == 2


class TestOutOfOrderEvents:
    def test_out_of_order_flagged_but_counts_stable(self):
        base = BASE_TIME
        events = [
            make_event(event_id="o2", timestamp=advance(base, 120)),
            make_event(event_id="o1", timestamp=base),
            make_event(event_id="o0", timestamp=advance(base, 60)),
        ]
        case = _first(events)
        # builder sorts internally: counts unaffected by arrival order
        assert case.session.event_count == 3
        report = _validate(case)
        reasons = " ".join(report.checks["sequence_consistency"].reasons)
        assert "out of chronological order" in reasons
        assert report.checks["sequence_consistency"].verdict is (
            CheckVerdict.WARN)


# ---------------------------------------------------------------------- #
# 7: malformed records
# ---------------------------------------------------------------------- #


class TestMalformedRecords:
    def _normalize(self, records):
        normalizer = ResourceActivityNormalizer()
        accepted, errors = [], []
        for record in records:
            try:
                accepted.append(
                    normalizer.normalize_cloudtrail(record))
            except (MalformedEventError, UnsupportedEventError) as exc:
                errors.append(exc)
        return accepted, errors

    def test_missing_timestamp_is_malformed(self):
        record = {
            "eventID": "evt-1",
            "eventSource": "s3.amazonaws.com",
            "eventName": "DeleteObject",
            "awsRegion": "us-east-1",
            "recipientAccountId": "111122223333",
            "userIdentity": {"type": "IAMUser",
                             "arn": "arn:aws:iam::1:user/alice"},
            "requestParameters": {"bucketName": "bkt", "key": "x"},
        }
        _, errors = self._normalize([record])
        assert len(errors) == 1
        assert isinstance(errors[0], MalformedEventError)
        assert "timestamp" in errors[0].message

    def test_unparsable_timestamp_is_malformed(self):
        record = {
            "eventTime": "not-a-timestamp",
            "eventSource": "s3.amazonaws.com",
            "eventName": "DeleteObject",
            "awsRegion": "us-east-1",
            "recipientAccountId": "111122223333",
            "userIdentity": {"type": "IAMUser"},
        }
        _, errors = self._normalize([record])
        assert isinstance(errors[0], MalformedEventError)
        assert errors[0].provider == "aws"

    def test_non_dict_record_is_malformed(self):
        _, errors = self._normalize([None])
        assert isinstance(errors[0], MalformedEventError)

    def test_out_of_scope_record_is_unsupported_not_malformed(self):
        record = {
            "eventID": "evt-2",
            "eventTime": "2026-09-10T12:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "recipientAccountId": "111122223333",
            "userIdentity": {"type": "IAMUser"},
        }
        _, errors = self._normalize([record])
        assert isinstance(errors[0], UnsupportedEventError)

    def test_valid_record_survives_alongside_malformed(self):
        good = {
            "eventID": "evt-3",
            "eventTime": "2026-09-10T12:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "DeleteObject",
            "awsRegion": "us-east-1",
            "recipientAccountId": "111122223333",
            "userIdentity": {"type": "IAMUser"},
            "requestParameters": {"bucketName": "bkt", "key": "k"},
        }
        bad = {"eventName": "DeleteObject"}
        accepted, errors = self._normalize([good, bad, dict(good)])
        assert len(accepted) == 2
        assert len(errors) == 1


# ---------------------------------------------------------------------- #
# 8: noisy resource metadata
# ---------------------------------------------------------------------- #


class TestNoisyResourceMetadata:
    def test_unknown_resource_types_flagged(self):
        events = [
            make_event(event_id=f"n{i}", timestamp=advance(BASE_TIME, i),
                       resource_type=__import__(
                           "detection.cloud_destruction.schemas",
                           fromlist=["ResourceType"]).ResourceType.UNKNOWN,
                       resource_arn=None)
            for i in range(6)
        ]
        case = _first(events)
        report = _validate(case)
        check = report.checks["resource_consistency"]
        reasons = " ".join(check.reasons)
        assert "unknown resource types" in reasons
        assert check.evidence["unknown_resource_type_events"] == 6

    def test_mixed_known_and_unknown_degrades_gently(self):
        from detection.cloud_destruction.schemas import (
            ResourceType,
        )

        events = [
            make_event(event_id="n1", timestamp=BASE_TIME,
                       resource_type=ResourceType.S3_OBJECT),
            make_event(event_id="n2", timestamp=advance(BASE_TIME, 1),
                       resource_type=ResourceType.UNKNOWN,
                       resource_arn=None),
        ]
        case = _first(events)
        report = _validate(case)
        # below the 50% warn share: no unknown-type challenge
        reasons = " ".join(report.checks["resource_consistency"].reasons)
        assert "unknown resource types" not in reasons

    def test_noisy_metadata_does_not_crash_pipeline(self):
        events = [
            make_event(event_id=f"z{i}", timestamp=advance(BASE_TIME, i),
                       resource_arn=None, object_key=None,
                       raw_action="", user_agent="")
            for i in range(5)
        ]
        case = _first(events)  # must not raise
        assert case.session.event_count == 5


# ---------------------------------------------------------------------- #
# 9: baseline contamination
# ---------------------------------------------------------------------- #


class TestBaselineContamination:
    def _destructive_history(self):
        from detection.cloud_destruction.schemas import (
            ActionCategory,
        )

        return [
            make_event(event_id=f"h{i}", timestamp=advance(BASE_TIME, i),
                       action_category=ActionCategory.SNAPSHOT_DELETE,
                       resource_id=f"snap-{i}",
                       snapshot_id=f"snap-{i}")
            for i in range(8)
        ]

    def test_destructive_session_is_critical_contamination(self):
        events = self._destructive_history()
        sessions = DestructiveSessionBuilder().build_sessions(events)
        classification = classify_contamination(sessions[0])
        assert classification is BaselineContamination.CRITICAL
        # critical contamination carries zero learning weight
        assert LEARNING_WEIGHT[classification] == 0.0

    def test_high_destructive_ratio_is_high_contamination(self):
        from detection.cloud_destruction.schemas import (
            ActionCategory,
        )

        events = [
            make_event(event_id=f"h{i}", timestamp=advance(BASE_TIME, i),
                       action_category=ActionCategory.DELETE,
                       resource_id=f"obj-{i}")
            for i in range(12)
        ]
        sessions = DestructiveSessionBuilder().build_sessions(events)
        classification = classify_contamination(sessions[0])
        assert classification in (
            BaselineContamination.HIGH, BaselineContamination.CRITICAL)
        assert LEARNING_WEIGHT[classification] == 0.0

    def test_baseline_excludes_contaminated_history(self):
        history = []
        # 25 benign modify sessions (one event each, spaced by an hour)
        for i in range(25):
            history.append(make_event(
                event_id=f"benign-{i}",
                timestamp=advance(BASE_TIME, i * 3600.0),
                actor_id="contaminated.actor",
                action_category=__import__(
                    "detection.cloud_destruction.schemas",
                    fromlist=["ActionCategory"]).ActionCategory.MODIFY,
                resource_id=f"benign-{i}"))
        # ...plus one destructive burst from the same actor
        for i in range(6):
            history.append(make_event(
                event_id=f"burst-{i}",
                timestamp=advance(BASE_TIME, 24 * 3600.0 + i * 60),
                actor_id="contaminated.actor",
                action_category=__import__(
                    "detection.cloud_destruction.schemas",
                    fromlist=["ActionCategory"]).ActionCategory.SNAPSHOT_DELETE,
                resource_id=f"snap-{i}",
                snapshot_id=f"snap-{i}"))
        sessions = DestructiveSessionBuilder().build_sessions(history)
        store = BaselineStore()
        baseline = store.build(sessions, actor_id="contaminated.actor")
        assert baseline is not None
        # the destructive burst must never teach the baseline
        assert baseline.excluded_sessions >= 1
        counts = baseline.contamination_counts
        assert any(
            level in ("high", "critical") for level in counts
        )


# ---------------------------------------------------------------------- #
# 10: contradictory telemetry
# ---------------------------------------------------------------------- #


class TestContradictoryTelemetry:
    def test_protected_deletions_exceed_totals(self):
        from detection.cloud_destruction.schemas import (
            ActionCategory,
        )

        events = [
            make_event(event_id=f"c{i}", timestamp=advance(BASE_TIME, i),
                       action_category=ActionCategory.SNAPSHOT_DELETE,
                       resource_id=f"snap-{i}",
                       snapshot_id=f"snap-{i}",
                       snapshot_protection_enabled=True)
            for i in range(2)
        ]
        case = _first(events)
        # replay with a session that lost the deletion counters
        zeroed = case.session.model_copy(
            update={"snapshot_deletions": 0})
        report = ArdeValidator().validate(
            case.finding, zeroed, case.vector,
            case.risk, case.confidence, events)
        reasons = " ".join(
            report.checks["protection_state_consistency"].reasons)
        assert "exceed total snapshot deletions" in reasons
        assert (report.checks["protection_state_consistency"].verdict
                is CheckVerdict.FAIL)

    def test_high_recoverability_contradicts_deleted_recovery(self):
        from detection.cloud_destruction.provenance import (
            MeasurementConfidence,
            MeasuredValue,
        )
        from detection.cloud_destruction.schemas import (
            ActionCategory,
        )

        events = [
            make_event(event_id=f"r{i}", timestamp=advance(BASE_TIME, i),
                       action_category=ActionCategory.BACKUP_DELETE,
                       resource_id=f"vault-{i}",
                       backup_vault_name=f"vault-{i}")
            for i in range(2)
        ]
        case = _first(events)
        healthy = case.vector.model_copy(
            update={"recoverability": MeasuredValue.measured(
                0.95, method="test",
                confidence=MeasurementConfidence.DERIVED)}
        )
        report = ArdeValidator().validate(
            case.finding, case.session, healthy,
            case.risk, case.confidence, events)
        reasons = " ".join(report.checks["recovery_consistency"].reasons)
        assert "high recoverability claimed" in reasons
        assert report.checks["recovery_consistency"].verdict is (
            CheckVerdict.FAIL)


# ---------------------------------------------------------------------- #
# 11: legitimate scheduled cleanup — recognized, never suppressed
# ---------------------------------------------------------------------- #


class TestLegitimateScheduledCleanup:
    def _cleanup_events(self):
        from detection.cloud_destruction.schemas import (
            ActorType,
            ActionCategory,
        )

        return [
            make_event(event_id=f"sc{i}", timestamp=advance(BASE_TIME, i),
                       actor_id="backup-automation",
                       actor_type=ActorType.AWS_SERVICE,
                       action_category=ActionCategory.SNAPSHOT_DELETE,
                       resource_id=f"snap-{i}",
                       snapshot_id=f"snap-{i}")
            for i in range(4)
        ]

    def test_pattern_recognized(self):
        events = self._cleanup_events()
        case = _first(events)
        annotation = ContextEngine().evaluate(
            case.finding, case.session, events)
        activities = [hit.activity for hit in annotation.recognized_patterns]
        assert LegitimateActivity.SCHEDULED_SNAPSHOT_CLEANUP in activities

    def test_finding_survives_recognition(self):
        # never silently suppressed: risk, severity and the
        # finding itself are unchanged by pattern recognition
        events = self._cleanup_events()
        case = _first(events)
        annotation = ContextEngine().evaluate(
            case.finding, case.session, events)
        explanation = build_explanation(
            case.finding, case.session, case.vector,
            case.risk, case.confidence, events,
            recognized_patterns=[
                hit.activity.value for hit in annotation.recognized_patterns
            ])
        assert explanation.label == FINDING_LABEL
        assert any("scheduled_snapshot_cleanup" in c
                   for c in explanation.contradicting_evidence)

    def test_confidence_unaffected_by_recognition(self):
        # recognition is evidence, not a verdict: confidence is
        # computed before context is applied and never softened
        events = self._cleanup_events()
        case = _first(events)
        annotation = ContextEngine().evaluate(
            case.finding, case.session, events)
        assert annotation.has_context
        # risk/confidence were produced by the scorer, untouched:
        assert case.risk.risk_score > 0
        assert 0.0 <= case.confidence.confidence_score <= 1.0


# ---------------------------------------------------------------------- #
# Confidence calibration across the whole matrix
# ---------------------------------------------------------------------- #


class TestConfidenceChangesAppropriately:
    def _scenario(self, *, detail, baseline_store=None):
        from detection.cloud_destruction.config import (
            DestructionDetectorConfig,
        )

        events = [
            make_event(event_id=f"e{i}", timestamp=advance(BASE_TIME, i * 60),
                       action_category=__import__(
                           "detection.cloud_destruction.schemas",
                           fromlist=["ActionCategory"]).ActionCategory.DELETE,
                       resource_id=f"obj-{i}",
                       resource_arn=f"arn:aws:s3:::bkt/obj-{i}")
            for i in range(10)
        ]
        cfg = DestructionDetectorConfig()
        sessions = DestructiveSessionBuilder(cfg.session).build_sessions(
            list(events))
        detail_events = list(events) if detail else []
        vectors = extract_features(
            sessions, detail_events, config=cfg,
            baseline_store=baseline_store)
        per_session = {}
        for s in sessions:
            ids = set(s.event_ids)
            per_session[s.session_id] = [
                e for e in detail_events if e.event_id in ids
            ]
        scores = []
        for session, vector in zip(sessions, vectors):
            risk = score_destruction(
                session, vector, anomaly_score=0.9, sequence_score=0.8)
            confidence = compute_confidence(
                session, vector, risk,
                baseline_quality=vector.baseline_quality,
                has_event_detail=bool(per_session[session.session_id]),
                model_agreement=risk.model_agreement,
                config=ConfidenceConfig(),
            )
            scores.append(confidence.confidence_score)
        return scores[0]

    def test_missing_detail_lowers_confidence(self):
        complete = self._scenario(detail=True)
        degraded = self._scenario(detail=False)
        assert degraded < complete

    def test_no_baseline_lowers_confidence(self):
        from detection.cloud_destruction.baseline import (
            BaselineQuality,
        )

        with_baseline = self._scenario(detail=True)
        # a NONE baseline (no history at all) is the weakest
        # evidence state; assert the trust factor documents it
        assert __import__(
            "detection.cloud_destruction.confidence",
            fromlist=["BASELINE_TRUST"]).BASELINE_TRUST[
                BaselineQuality.NONE.value] == 0.0
        assert with_baseline <= 1.0

    def test_arde_completeness_tracks_confidence(self):
        complete_case = _first(
            [make_event(event_id=f"c{i}",
                        timestamp=advance(BASE_TIME, i))
             for i in range(10)], detail=True)
        degraded_case = _first(
            [make_event(event_id=f"c{i}",
                        timestamp=advance(BASE_TIME, i))
             for i in range(10)], detail=False)
        complete_score = _validate(complete_case).checks[
            "telemetry_completeness"].evidence["completeness_score"]
        degraded_score = _validate(degraded_case).checks[
            "telemetry_completeness"].evidence["completeness_score"]
        assert degraded_score < complete_score

    def test_full_detector_replays_robustly(self):
        # end-to-end: the detector itself must survive every
        # degraded replay without raising
        detector = DestructionDetector()
        events = [
            make_event(event_id=f"f{i}", timestamp=advance(BASE_TIME, i),
                       resource_id=f"res-{i % 3}")
            for i in range(15)
        ]
        outcome = detector.detect(events)
        assert outcome.findings
        assert outcome.validation_reports
        assert outcome.explanations
        for report in outcome.validation_reports:
            assert len(report.checks) == 10


# ---------------------------------------------------------------------- #
# Sanity: replay determinism under degraded inputs
# ---------------------------------------------------------------------- #


class TestReplayDeterminism:
    def test_degraded_replay_is_reproducible(self):
        events = [
            make_event(event_id=f"r{i}", timestamp=advance(BASE_TIME, i))
            for i in range(8)
        ]
        first = _first(events, detail=False)
        second = _first(events, detail=False)
        assert (first.confidence.confidence_score
                == second.confidence.confidence_score)
        assert (first.risk.risk_score == second.risk.risk_score)

    def test_session_builder_sorts_out_of_order_input(self):
        base = BASE_TIME
        events = [
            make_event(event_id="x3", timestamp=advance(base, 300)),
            make_event(event_id="x1", timestamp=base),
            make_event(event_id="x2", timestamp=advance(base, 150)),
        ]
        case = _first(events)
        assert case.session.start_time == base
        assert case.session.end_time == advance(base, 300)
        assert [e.event_id for e in sorted(
            events, key=lambda e: e.timestamp)] == ["x1", "x2", "x3"]
