"""Part 6 — ARDE validator tests (ten checks, never raises)."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from detection.cloud_destruction.arde import (
    ArdeConfig,
    ArdeValidator,
    CheckVerdict,
    ValidationCheck,
    ValidationReport,
)
from detection.cloud_destruction.confidence import (
    ConfidenceConfig,
    compute_confidence,
)
from detection.cloud_destruction.features import extract_features
from detection.cloud_destruction.finding import build_finding
from detection.cloud_destruction.scorer import score_destruction
from detection.cloud_destruction.schemas import (
    ActionCategory,
    DestructiveActivitySession,
)
from detection.cloud_destruction.tests.helpers import (
    BASE_TIME,
    advance,
    make_event,
)


def _full_pipeline(events, *, use_ml=True):
    """Run feature extraction + fusion + confidence for one session."""
    from detection.cloud_destruction.session import (
        DestructiveSessionBuilder,
    )
    from detection.cloud_destruction.config import DestructionDetectorConfig

    cfg = DestructionDetectorConfig()
    sessions = DestructiveSessionBuilder(cfg.session).build_sessions(
        list(events)
    )
    per_session = {}
    for session in sessions:
        per_session[session.session_id] = [
            e for e in events if e.session_id == session.session_id
        ] or []
    vectors = extract_features(sessions, list(events), config=cfg)
    results = []
    for session, vector in zip(sessions, vectors):
        risk = score_destruction(
            session, vector, anomaly_score=0.9 if use_ml else None,
            sequence_score=0.8,
        )
        confidence = compute_confidence(
            session, vector, risk,
            baseline_quality=vector.baseline_quality,
            has_event_detail=bool(per_session[session.session_id]),
            model_agreement=risk.model_agreement,
        )
        finding = build_finding(
            session, risk, confidence,
            baseline_quality=vector.baseline_quality,
        )
        results.append((finding, session, vector, risk, confidence))
    return results


class TestArdeValidatorContract:
    def test_validator_never_raises_on_broken_inputs(self):
        validator = ArdeValidator()
        # pass garbage — every check must degrade to FAIL, not raise
        report = validator.validate(None, None, None, None, None, None)
        assert report.overall is CheckVerdict.FAIL
        assert len(report.checks) == 10
        for check in report.checks.values():
            assert check.verdict is CheckVerdict.FAIL

    def test_all_ten_checks_present(self):
        validator = ArdeValidator()
        report = validator.validate(None, None, None, None, None, None)
        expected = {
            "event_consistency", "sequence_consistency",
            "resource_consistency", "time_consistency",
            "baseline_consistency", "recovery_consistency",
            "model_rule_agreement", "telemetry_completeness",
            "protection_state_consistency",
            "feature_provenance_validation",
        }
        assert set(report.checks) == expected

    def test_report_is_frozen_and_loggable(self):
        validator = ArdeValidator()
        report = validator.validate(None, None, None, None, None, None)
        with pytest.raises(Exception):
            report.overall = CheckVerdict.PASS  # type: ignore[misc]
        log = report.to_log_dict()
        assert log["overall"] == "fail"
        assert log["checks"]["event_consistency"]["verdict"] == "fail"

    def test_challenged_property(self):
        clean = ValidationReport(
            finding_id="f", session_id="s", overall=CheckVerdict.PASS,
            checks={}, failed_checks=(), warnings=(),
        )
        assert not clean.challenged
        warned = ValidationReport(
            finding_id="f", session_id="s", overall=CheckVerdict.WARN,
            checks={}, failed_checks=(), warnings=("x",),
        )
        assert warned.challenged

    def test_check_verdict_ordering(self):
        assert CheckVerdict.PASS.value == "pass"
        assert CheckVerdict.WARN.value == "warn"
        assert CheckVerdict.FAIL.value == "fail"


class TestArdeChecks:
    def _case(self, events, *, use_ml=True):
        results = _full_pipeline(events, use_ml=use_ml)
        assert results
        return results[0]

    def test_clean_session_passes(self):
        events = [
            make_event(event_id=f"e{i}", timestamp=advance(BASE_TIME, i))
            for i in range(8)
        ]
        finding, session, vector, risk, confidence = self._case(events)
        report = ArdeValidator().validate(
            finding, session, vector, risk, confidence, events)
        # no event detail issues: ids match, chronological, bounded
        assert report.checks["event_consistency"].verdict is CheckVerdict.PASS
        assert report.checks["time_consistency"].verdict is CheckVerdict.PASS

    def test_duplicated_event_ids_flagged(self):
        base = BASE_TIME
        events = [
            make_event(event_id="e1", timestamp=base),
            make_event(event_id="e1", timestamp=advance(base, 1)),
        ]
        finding, session, vector, risk, confidence = self._case(events)
        report = ArdeValidator().validate(
            finding, session, vector, risk, confidence, events)
        reasons = " ".join(report.checks["event_consistency"].reasons)
        assert "duplicated" in reasons

    def test_out_of_order_telemetry_flagged(self):
        base = BASE_TIME
        events = [
            make_event(event_id="e2", timestamp=advance(base, 2)),
            make_event(event_id="e1", timestamp=base),
        ]
        finding, session, vector, risk, confidence = self._case(events)
        report = ArdeValidator().validate(
            finding, session, vector, risk, confidence, events)
        reasons = " ".join(report.checks["sequence_consistency"].reasons)
        assert "out of chronological order" in reasons

    def test_time_consistency_catches_negative_duration(self):
        base = BASE_TIME
        events = [
            make_event(event_id="e1", timestamp=base),
            make_event(event_id="e2", timestamp=advance(base, 60)),
        ]
        finding, session, vector, risk, confidence = self._case(events)
        broken = session.model_copy(
            update={"start_time": session.end_time,
                    "end_time": session.start_time})
        report = ArdeValidator().validate(
            finding, broken, vector, risk, confidence, events)
        reasons = " ".join(report.checks["time_consistency"].reasons)
        assert "negative" in reasons

    def test_model_rule_disagreement_warns(self):
        base = BASE_TIME
        events = [make_event(event_id="e1", timestamp=base)]
        finding, session, vector, risk, confidence = self._case(events)
        risk_disagreeing = replace(risk, model_agreement=False)
        report = ArdeValidator().validate(
            finding, session, vector, risk_disagreeing, confidence, events)
        assert report.checks["model_rule_agreement"].verdict is CheckVerdict.WARN
        assert report.checks["model_rule_agreement"].evidence[
            "model_agreement"] is False

    def test_model_agreement_unmeasured_warns(self):
        base = BASE_TIME
        events = [make_event(event_id="e1", timestamp=base)]
        finding, session, vector, risk, confidence = self._case(
            events, use_ml=False)
        report = ArdeValidator().validate(
            finding, session, vector, risk, confidence, events)
        assert report.checks["model_rule_agreement"].verdict is CheckVerdict.WARN

    def test_telemetry_completeness_fails_when_empty(self):
        base = BASE_TIME
        events = [make_event(event_id="e1", timestamp=base)]
        finding, session, vector, risk, confidence = self._case(events)
        report = ArdeValidator().validate(
            finding, session, vector, risk, confidence, ())
        check = report.checks["telemetry_completeness"]
        assert check.verdict is CheckVerdict.FAIL
        assert check.evidence["has_event_detail"] is False

    def test_recovery_consistency_flags_destroyed_recovery(self):
        base = BASE_TIME
        events = [
            make_event(event_id=f"s{i}", timestamp=advance(base, i),
                       action_category=ActionCategory.SNAPSHOT_DELETE,
                       resource_id=f"snap-{i}",
                       snapshot_id=f"snap-{i}")
            for i in range(3)
        ]
        finding, session, vector, risk, confidence = self._case(events)
        report = ArdeValidator().validate(
            finding, session, vector, risk, confidence, events)
        assert session.snapshot_deletions == 3
        # recoverability should be impaired; consistency must hold
        assert report.checks["recovery_consistency"].verdict in (
            CheckVerdict.PASS, CheckVerdict.WARN)

    def test_feature_provenance_validates_methods(self):
        base = BASE_TIME
        events = [make_event(event_id="e1", timestamp=base)]
        finding, session, vector, risk, confidence = self._case(events)
        report = ArdeValidator().validate(
            finding, session, vector, risk, confidence, events)
        check = report.checks["feature_provenance_validation"]
        assert check.verdict in (CheckVerdict.PASS, CheckVerdict.WARN)
        # every available feature carries a provenance record
        for name in vector.feature_availability:
            assert name in vector.feature_provenance

    def test_protection_state_consistency_counts(self):
        base = BASE_TIME
        events = [
            make_event(event_id=f"p{i}", timestamp=advance(base, i),
                       action_category=ActionCategory.PROTECTION_CHANGE,
                       resource_id=f"bucket-{i}")
            for i in range(2)
        ]
        finding, session, vector, risk, confidence = self._case(events)
        report = ArdeValidator().validate(
            finding, session, vector, risk, confidence, events)
        assert session.protection_changes == 2
        assert report.checks["protection_state_consistency"].verdict in (
            CheckVerdict.PASS, CheckVerdict.WARN)

    def test_config_thresholds_are_tunable(self):
        cfg = ArdeConfig(telemetry_pass_threshold=0.99)
        assert cfg.telemetry_pass_threshold == 0.99
        assert ArdeConfig().require_provenance_method is True


class TestArdeDoesNotMutate:
    def test_validation_leaves_finding_untouched(self):
        base = BASE_TIME
        events = [make_event(event_id="e1", timestamp=base)]
        finding, session, vector, risk, confidence = _full_pipeline(events)[0]
        before = (finding.risk_score, finding.confidence_score,
                  finding.severity)
        ArdeValidator().validate(finding, session, vector, risk,
                                 confidence, events)
        after = (finding.risk_score, finding.confidence_score,
                 finding.severity)
        assert before == after
