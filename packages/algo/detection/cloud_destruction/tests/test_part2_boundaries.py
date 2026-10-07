"""Boundary tests: which layers may emit what.

Part 3 status: the full pipeline computes real risk, confidence and
findings. These tests pin the remaining boundaries:

- canonical events and Part 1 sessions carry **no** score fields — risk
  lives only on findings / fusion outputs, never on raw telemetry models;
- the Part 2 feature vector is evidence-shaped (no destruction score, no
  verdict fields) — fusion happens in the scorer, on top;
- **risk and confidence are separate values** and never trivially derived
  from each other;
- scores are always bounded in ``[0, 1]`` — no magic "perfect" scores.
"""

from __future__ import annotations

import pytest

from detection.cloud_destruction.session import DestructiveSessionBuilder
from detection.cloud_destruction.tests.helpers import make_event


def test_session_carries_no_risk_score_field():
    session = DestructiveSessionBuilder().build_sessions([make_event()])[0]
    dumped = session.model_dump()
    assert "risk_score" not in dumped
    assert "destruction_score" not in dumped
    assert session.risk_state == "analyzed"  # observational state only


def test_event_carries_no_score_fields():
    dumped = make_event().model_dump()
    for forbidden in ("risk", "score", "severity", "verdict", "is_ransomware"):
        assert not any(forbidden in key for key in dumped), forbidden


def test_feature_vector_carries_no_verdict_fields():
    from detection.cloud_destruction.features import SessionFeatureVector

    dumped = SessionFeatureVector(session_id="s").model_dump()
    for forbidden in ("destruction_score", "severity", "verdict", "is_ransomware"):
        assert forbidden not in dumped, forbidden


class TestPart3Boundaries:
    def test_detector_produces_findings_not_exceptions(self):
        """Part 3: detect() works and emits audit-complete findings."""
        from detection.cloud_destruction.detector import DestructionDetector

        outcome = DestructionDetector().detect([make_event(event_id="e1")])
        assert len(outcome.findings) == len(outcome.sessions)
        for finding in outcome.findings:
            assert 0.0 <= finding.risk_score <= 1.0
            assert 0.0 <= finding.confidence_score <= 1.0
            assert finding.scoring_version
            assert finding.rule_version
            assert finding.feature_version

    def test_risk_and_confidence_are_separate_values(self):
        """Risk ≠ confidence, and confidence is never risk/100."""
        from detection.cloud_destruction.detector import DestructionDetector

        outcome = DestructionDetector().detect(
            [make_event(event_id="e1"), make_event(event_id="e2", actor_id="other")]
        )
        for finding in outcome.findings:
            assert finding.risk_score != finding.confidence_score or (
                finding.risk_score == 0.0
            )  # trivially-equal zero is the only allowed coincidence

    def test_supervised_slot_requires_declared_labels(self):
        """The supervised slot never fabricates labels or trains silently."""
        from detection.cloud_destruction.supervised import SupervisedDetector

        detector = SupervisedDetector()
        assert not detector.is_fitted
        assert detector.predict_row([0.1, 0.2]) is None
        with pytest.raises(ValueError):
            from detection.cloud_destruction.supervised import SupervisedTrainingData

            SupervisedTrainingData(rows=[[1.0]], labels=[1], label_source="made-up")
