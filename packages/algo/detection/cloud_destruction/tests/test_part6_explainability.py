"""Part 6 — destructive-behavior categorization & explainability."""

from __future__ import annotations

import json

import pytest

from detection.cloud_destruction.confidence import (
    ConfidenceConfig,
    compute_confidence,
)
from detection.cloud_destruction.explainability import (
    CATEGORY_THRESHOLDS,
    DestructiveBehaviorCategory,
    Explanation,
    FINDING_LABEL,
    build_explanation,
    categorize,
    telemetry_completeness_level,
)
from detection.cloud_destruction.features import extract_features
from detection.cloud_destruction.finding import build_finding
from detection.cloud_destruction.schemas import (
    ActionCategory,
    DestructiveActivitySession,
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


def _run(events, *, baseline_store=None, anomaly_score=0.9):
    """Feature extraction + fusion + confidence for one session."""
    from detection.cloud_destruction.config import (
        DestructionDetectorConfig,
    )

    cfg = DestructionDetectorConfig()
    sessions = DestructiveSessionBuilder(cfg.session).build_sessions(
        list(events)
    )
    assert sessions
    vectors = extract_features(
        sessions, list(events), baseline_store=baseline_store,
        config=cfg,
    )
    results = []
    for session, vector in zip(sessions, vectors):
        risk = score_destruction(
            session, vector, anomaly_score=anomaly_score,
            sequence_score=0.8,
        )
        confidence = compute_confidence(
            session, vector, risk,
            baseline_quality=vector.baseline_quality,
            has_event_detail=bool(events),
            model_agreement=risk.model_agreement,
            config=ConfidenceConfig(),
        )
        finding = build_finding(
            session, risk, confidence,
            baseline_quality=vector.baseline_quality,
            recoverability=(
                vector.recoverability.value
                if vector.recoverability is not None
                and vector.recoverability.available
                else None
            ),
        )
        results.append((finding, session, vector, risk, confidence))
    return results


def _events(kind, count, *, distinct=1, actor="alice.admin",
            resource_prefix="res"):
    """Build ``count`` destructive events of one kind."""
    return [
        make_event(
            event_id=f"{kind}-{i}",
            timestamp=advance(BASE_TIME, i * 60),
            actor_id=actor,
            action_category=kind,
            resource_id=f"{resource_prefix}-{i % distinct}",
            resource_arn=(
                f"arn:aws:s3:::bucket/{resource_prefix}-"
                f"{i % distinct}"
            ),
            raw_action=f"svc:{kind.name}",
        )
        for i in range(count)
    ]


class TestCategorization:
    def test_mass_modification(self):
        events = _events(ActionCategory.MODIFY, 6, distinct=6)
        finding, session, vector, risk, conf = _run(events)[0]
        cats = categorize(session, vector)
        assert DestructiveBehaviorCategory.MASS_MODIFICATION in cats

    def test_mass_deletion_by_count(self):
        events = _events(ActionCategory.DELETE, 6, distinct=6)
        finding, session, vector, risk, conf = _run(events)[0]
        cats = categorize(session, vector)
        assert DestructiveBehaviorCategory.MASS_DELETION in cats

    def test_mass_deletion_by_destructive_volume(self):
        # 10 destructive events but only 2 distinct resources deleted
        events = _events(ActionCategory.DELETE, 10, distinct=2)
        finding, session, vector, risk, conf = _run(events)[0]
        cats = categorize(session, vector)
        assert DestructiveBehaviorCategory.MASS_DELETION in cats

    def test_version_destruction(self):
        events = _events(ActionCategory.VERSION_DELETE, 6, distinct=1)
        finding, session, vector, risk, conf = _run(events)[0]
        cats = categorize(session, vector)
        assert DestructiveBehaviorCategory.VERSION_DESTRUCTION in cats

    def test_recovery_destruction(self):
        events = _events(ActionCategory.SNAPSHOT_DELETE, 2, distinct=2)
        finding, session, vector, risk, conf = _run(events)[0]
        cats = categorize(session, vector)
        assert DestructiveBehaviorCategory.RECOVERY_DESTRUCTION in cats

    def test_protection_degradation(self):
        events = _events(ActionCategory.PROTECTION_CHANGE, 2, distinct=2)
        finding, session, vector, risk, conf = _run(events)[0]
        cats = categorize(session, vector)
        assert DestructiveBehaviorCategory.PROTECTION_DEGRADATION in cats

    def test_mass_rewrite(self):
        events = _events(ActionCategory.REWRITE, 6, distinct=6)
        finding, session, vector, risk, conf = _run(events)[0]
        cats = categorize(session, vector)
        assert DestructiveBehaviorCategory.MASS_REWRITE in cats

    def test_multi_resource_destruction(self):
        # exactly at the multi-resource threshold, below mass thresholds
        events = _events(ActionCategory.DELETE, 3, distinct=3)
        finding, session, vector, risk, conf = _run(events)[0]
        cats = categorize(session, vector)
        assert DestructiveBehaviorCategory.MULTI_RESOURCE_DESTRUCTION in cats
        assert DestructiveBehaviorCategory.MASS_DELETION not in cats

    def test_compound_when_categories_co_occur(self):
        events = (
            _events(ActionCategory.DELETE, 6, distinct=6)
            + _events(ActionCategory.PROTECTION_CHANGE, 2, distinct=2)
        )
        finding, session, vector, risk, conf = _run(events)[0]
        cats = categorize(session, vector)
        assert len(cats) >= 3
        assert (
            DestructiveBehaviorCategory.COMPOUND_DESTRUCTIVE_ACTIVITY
            in cats
        )

    def test_single_benign_event_uncategorized(self):
        events = _events(ActionCategory.MODIFY, 1, distinct=1)
        finding, session, vector, risk, conf = _run(events)[0]
        assert categorize(session, vector) == ()

    def test_thresholds_are_documented(self):
        assert CATEGORY_THRESHOLDS["mass_modification"] == 5
        assert CATEGORY_THRESHOLDS["mass_deletion"] == 5
        assert CATEGORY_THRESHOLDS["mass_rewrite"] == 5
        assert CATEGORY_THRESHOLDS["multi_resource"] == 3

    def test_eight_spec_categories_exist(self):
        assert len(DestructiveBehaviorCategory) == 8


class TestExplanationSpecBlock:
    def test_spec_block_shape(self):
        events = _events(ActionCategory.DELETE, 6, distinct=6)
        finding, session, vector, risk, conf = _run(events)[0]
        explanation = build_explanation(
            finding, session, vector, risk, conf, events)
        data = explanation.to_dict()
        for key in (
            "top_contributors", "supporting_evidence",
            "contradicting_evidence", "baseline_quality",
            "telemetry_completeness", "model_agreement",
        ):
            assert key in data
            assert isinstance(data[key], (list, str))

    def test_label_is_neutral(self):
        events = _events(ActionCategory.DELETE, 8, distinct=8)
        finding, session, vector, risk, conf = _run(events)[0]
        explanation = build_explanation(
            finding, session, vector, risk, conf, events)
        assert explanation.label == FINDING_LABEL
        assert explanation.label == "Potential cloud destructive activity"
        rendered = json.dumps(explanation.to_dict()).lower()
        assert "ransomware" not in rendered
        assert "confirmed" not in rendered

    def test_model_agreement_vocabulary(self):
        events = [make_event(event_id="e1", timestamp=BASE_TIME)]
        finding, session, vector, risk, conf = _run(events)[0]
        explanation = build_explanation(
            finding, session, vector, risk, conf, events)
        assert explanation.model_agreement in (
            "STRONG", "WEAK", "UNKNOWN")
        assert explanation.telemetry_completeness in (
            "HIGH", "MODERATE", "LOW")
        assert explanation.baseline_quality in (
            "GOOD", "LIMITED", "INSUFFICIENT", "NONE")

    def test_explanation_is_frozen_and_json_serializable(self):
        events = _events(ActionCategory.DELETE, 4, distinct=4)
        finding, session, vector, risk, conf = _run(events)[0]
        explanation = build_explanation(
            finding, session, vector, risk, conf, events)
        with pytest.raises(Exception):
            explanation.label = "x"  # type: ignore[misc]
        json.dumps(explanation.to_dict())

    def test_completeness_level_boundaries(self):
        assert telemetry_completeness_level(0.8) == "HIGH"
        assert telemetry_completeness_level(0.5) == "MODERATE"
        assert telemetry_completeness_level(0.1) == "LOW"


class TestAnalystQuestions:
    """The explanation must answer the nine analyst questions."""

    def _explanation(self, events, **kwargs):
        finding, session, vector, risk, conf = _run(events)[0]
        return build_explanation(
            finding, session, vector, risk, conf, events, **kwargs)

    def test_what_happened_counts_and_actor(self):
        events = _events(ActionCategory.DELETE, 6, distinct=6)
        explanation = self._explanation(events)
        assert "6 destructive events" in explanation.what_happened
        assert "alice.admin" in explanation.what_happened

    def test_which_resources_affected(self):
        events = _events(ActionCategory.DELETE, 3, distinct=3)
        explanation = self._explanation(events)
        assert set(explanation.resources_affected) <= set(
            session_resources(events))
        assert len(explanation.resources_affected) == 3

    def test_how_unusual_reports_top_contributors(self):
        events = _events(ActionCategory.DELETE, 6, distinct=6)
        explanation = self._explanation(events)
        assert explanation.how_unusual
        assert explanation.what_changed

    def test_what_was_normal_without_baseline(self):
        events = _events(ActionCategory.DELETE, 4, distinct=4)
        explanation = self._explanation(events)
        assert "baseline" in explanation.what_was_normal.lower()

    def test_recovery_mechanisms_affected(self):
        events = _events(ActionCategory.SNAPSHOT_DELETE, 3, distinct=3)
        explanation = self._explanation(events)
        assert any("snapshot" in m.lower()
                   for m in explanation.recovery_mechanisms_affected)

    def test_signals_contributed_and_contradicted(self):
        events = _events(ActionCategory.DELETE, 6, distinct=6)
        explanation = self._explanation(events)
        assert isinstance(explanation.signals_contributed, list)
        assert isinstance(explanation.signals_contradicted, list)

    def test_telemetry_missing_reports_unavailable_features(self):
        events = _events(ActionCategory.DELETE, 4, distinct=4)
        explanation = self._explanation(events)
        # no baseline => baseline-relative features are unavailable
        assert any(
            name.startswith("delete_rate_deviation")
            or "deviation" in name
            for name in explanation.telemetry_missing
        )


def session_resources(events):
    return [e.resource_arn for e in events]


class TestNeverInvents:
    """Every explanation string must trace to a measured value."""

    def test_top_contributor_phrase_traces_to_measured_value(self):
        # give the actor a real baseline so delete_rate_deviation exists.
        # GOOD quality needs >= 20 sessions spanning >= 7 days, so the
        # history is spread over ~8 days with 1-hour gaps (session
        # idle timeout is 30 minutes, so each event is its own session).
        from detection.cloud_destruction.baseline import BaselineStore

        history = [
            make_event(
                event_id=f"hist-{i}",
                timestamp=advance(BASE_TIME, i * 3600.0),
                actor_id="bob.archivist",
                action_category=ActionCategory.MODIFY,
                resource_id=f"hist-res-{i}",
                resource_arn=f"arn:aws:s3:::bucket/hist-res-{i}",
                raw_action="s3:PutObject",
            )
            for i in range(24 * 8)
        ]
        from detection.cloud_destruction.config import (
            DestructionDetectorConfig,
        )

        cfg = DestructionDetectorConfig()
        history_sessions = DestructiveSessionBuilder(
            cfg.session).build_sessions(history)
        assert len(history_sessions) >= 20
        store = BaselineStore()
        store.build(
            history_sessions, actor_id="bob.archivist",
            events=history,
        )
        target = _events(ActionCategory.DELETE, 8, distinct=8,
                         actor="bob.archivist")
        finding, session, vector, risk, conf = _run(
            target, baseline_store=store)[0]
        assert vector.baseline_quality.value == "good"
        explanation = build_explanation(
            finding, session, vector, risk, conf, target)
        measured = vector.delete_rate_deviation
        assert measured is not None and measured.available
        assert any(
            f"{measured.value:.1f}x baseline" in phrase
            for phrase in explanation.top_contributors
        )

    def test_top_contributors_capped_at_five(self):
        events = (
            _events(ActionCategory.DELETE, 8, distinct=8)
            + _events(ActionCategory.VERSION_DELETE, 6, distinct=1)
            + _events(ActionCategory.PROTECTION_CHANGE, 3, distinct=3)
        )
        finding, session, vector, risk, conf = _run(events)[0]
        explanation = build_explanation(
            finding, session, vector, risk, conf, events)
        assert 0 < len(explanation.top_contributors) <= 5

    def test_supporting_evidence_uses_session_counters(self):
        events = _events(ActionCategory.DELETE, 7, distinct=7)
        finding, session, vector, risk, conf = _run(events)[0]
        explanation = build_explanation(
            finding, session, vector, risk, conf, events)
        assert any(
            "7 destructive events" in s
            for s in explanation.supporting_evidence
        )
        assert any(
            "7 resources deleted" in s
            for s in explanation.supporting_evidence
        )

    def test_resources_affected_never_exceed_session(self):
        events = _events(ActionCategory.DELETE, 4, distinct=4)
        finding, session, vector, risk, conf = _run(events)[0]
        explanation = build_explanation(
            finding, session, vector, risk, conf, events)
        assert set(explanation.resources_affected) <= set(
            session.resources_touched)

    def test_risk_and_confidence_echo_detector_values(self):
        events = _events(ActionCategory.DELETE, 5, distinct=5)
        finding, session, vector, risk, conf = _run(events)[0]
        explanation = build_explanation(
            finding, session, vector, risk, conf, events)
        assert explanation.risk_score == risk.risk_score
        assert explanation.confidence_score == conf.confidence_score
        assert explanation.severity == finding.severity.value


class TestContradictingEvidence:
    def test_model_disagreement_contradicts(self):
        from dataclasses import replace

        events = _events(ActionCategory.DELETE, 5, distinct=5)
        finding, session, vector, risk, conf = _run(events)[0]
        disagreeing = replace(risk, model_agreement=False)
        explanation = build_explanation(
            finding, session, vector, disagreeing, conf, events)
        assert any(
            "disagrees" in c for c in explanation.contradicting_evidence)
        assert "model_rule_agreement" in explanation.signals_contradicted

    def test_arde_failures_contradict(self):
        from detection.cloud_destruction.arde import (
            ArdeValidator,
        )

        events = _events(ActionCategory.DELETE, 5, distinct=5)
        finding, session, vector, risk, conf = _run(events)[0]
        report = ArdeValidator().validate(
            finding, session, vector, risk, conf, ())  # empty telemetry
        explanation = build_explanation(
            finding, session, vector, risk, conf, events, report=report)
        assert any(
            c.startswith("ARDE") and "FAILED" in c
            for c in explanation.contradicting_evidence
        )

    def test_approved_activity_contradicts(self):
        events = _events(ActionCategory.DELETE, 5, distinct=5)
        finding, session, vector, risk, conf = _run(events)[0]
        approved = finding.model_copy(
            update={"approved_activity": {
                "approved": True,
                "justification": "scheduled cleanup",
            }}
        ) if hasattr(finding, "model_copy") else finding
        # dataclass: rebuild via build_finding with approved_activity
        approved = build_finding(
            session, risk, conf,
            baseline_quality=vector.baseline_quality,
            approved_activity={
                "approved": True,
                "justification": "scheduled cleanup",
            },
        )
        explanation = build_explanation(
            approved, session, vector, risk, conf, events)
        assert any(
            "legitimate activity" in c
            for c in explanation.contradicting_evidence
        )

    def test_recognized_patterns_contradict(self):
        events = _events(ActionCategory.DELETE, 5, distinct=5)
        finding, session, vector, risk, conf = _run(events)[0]
        explanation = build_explanation(
            finding, session, vector, risk, conf, events,
            recognized_patterns=["s3_lifecycle_expiration"],
        )
        assert any(
            "legitimate pattern" in c
            for c in explanation.contradicting_evidence
        )

    def test_high_recoverability_contradicts(self):
        events = _events(ActionCategory.DELETE, 5, distinct=5)
        finding, session, vector, risk, conf = _run(events)[0]
        # force recoverability to a healthy value
        healthy = vector.model_copy(
            update={"recoverability": _measured(0.95)})
        explanation = build_explanation(
            finding, session, healthy, risk, conf, events)
        assert any(
            "recovery mechanisms still available" in c
            for c in explanation.contradicting_evidence
        )

    def test_weak_baseline_contradicts(self):
        events = _events(ActionCategory.DELETE, 5, distinct=5)
        finding, session, vector, risk, conf = _run(events)[0]
        assert vector.baseline_quality.value == "none"
        explanation = build_explanation(
            finding, session, vector, risk, conf, events)
        assert any(
            "baseline-relative evidence is weak" in c
            for c in explanation.contradicting_evidence
        )


def _measured(value):
    from detection.cloud_destruction.provenance import (
        MeasuredValue,
        MeasurementConfidence,
    )

    return MeasuredValue.measured(
        value, method="test", confidence=MeasurementConfidence.DERIVED)
