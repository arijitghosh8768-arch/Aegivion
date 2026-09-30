"""Scoring pipeline tests: variants, versioning, risk-vs-confidence separation."""

from __future__ import annotations

import pytest

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    AvailableFeature,
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.confidence_engine import ConfidenceState
from algo.data_exfiltration.data_exfiltration.ml.isolation_forest import IsolationForest
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack
from algo.data_exfiltration.data_exfiltration.schemas import FindingSeverity


def _fset(session_id: str, risk: float, quality: float = 0.9) -> BehavioralFeatureSet:
    fset = BehavioralFeatureSet(
        subject_id="actor", session_id=session_id, actor_id="actor",
        computed_at_epoch_ms=1000.0, baseline_quality=quality,
        baseline_scope_used="personal" if quality >= 0.5 else "none",
    )
    def _f(v: float) -> AvailableFeature:
        return AvailableFeature(value=v, availability=FeatureAvailability.OBSERVED)

    fset.volume_score = _f(risk)
    fset.object_count_score = _f(min(1.0, risk * 0.8))
    fset.request_rate_score = _f(min(1.0, risk * 0.7))
    fset.destination_score = _f(min(1.0, risk * 0.9))
    fset.access_pattern_score = _f(min(1.0, risk * 0.6))
    fset.sensitivity_score = _f(0.3 if risk < 0.5 else 0.85)
    fset.time_score = _f(min(1.0, risk * 0.4))
    fset.actor_resource_score = _f(min(1.0, risk * 0.5))
    fset.egress_score = _f(min(1.0, risk * 0.8))
    fset.session_features["feature_vector"] = [
        risk, risk * 0.8, risk * 0.7, risk * 0.6, risk * 0.9, 0.1, 0.1, 0.1, 0.1,
        risk * 0.6, risk * 0.5, risk * 0.4, risk * 0.5, 0.3, 0.5, risk * 0.8, 0.1,
    ]
    return fset.finalize()


class TestScoringStack:
    def test_variant_a_rules_only(self) -> None:
        stack = ScoringStack(variant="A")
        scored = stack.score(_fset("s1", 0.05))
        assert scored.risk_score >= 0.0
        assert scored.fired_rules == [] or scored.rules_score is not None
        assert scored.model.variant == "A"

    def test_variant_b_fuses_features(self) -> None:
        stack = ScoringStack(variant="B")
        quiet = stack.score(_fset("s-quiet", 0.05))
        loud = stack.score(_fset("s-loud", 0.9))
        assert loud.risk_score > quiet.risk_score
        assert set(loud.contributions) >= {"volume", "destination", "sensitivity"}

    def test_variant_c_adds_anomaly_component(self) -> None:
        # train a tiny deterministic IF on normal-shaped vectors
        rows = []
        for i in range(40):
            r = 0.05 + (i % 5) * 0.01
            rows.append([r, r * 0.8, r * 0.7, r * 0.6, r * 0.9, 0.1, 0.1, 0.1, 0.1,
                         r * 0.6, r * 0.5, r * 0.4, r * 0.5, 0.3, 0.5, r * 0.8, 0.1])
        model = IsolationForest(n_estimators=30, max_samples=32, seed=42).fit(rows)

        stack = ScoringStack(variant="C", anomaly_model=model)
        quiet = stack.score(_fset("s-quiet", 0.05))
        loud = stack.score(_fset("s-loud", 0.9))
        assert quiet.anomaly_score is not None and loud.anomaly_score is not None
        assert loud.risk_score > quiet.risk_score
        assert "anomaly" in loud.contributions

    def test_variant_c_without_model_renormalizes(self) -> None:
        stack = ScoringStack(variant="C")  # no anomaly model fitted
        scored = stack.score(_fset("s1", 0.5))
        assert scored.anomaly_score is None
        assert "anomaly" in scored.missing_components

    def test_confidence_state_present(self) -> None:
        stack = ScoringStack(variant="B")
        scored = stack.score(_fset("s1", 0.5))
        assert scored.confidence_state in (
            ConfidenceState.HEURISTIC.value,
            ConfidenceState.CALIBRATED.value,
            ConfidenceState.INSUFFICIENT_DATA.value,
        )

    def test_risk_and_confidence_are_separate_fields(self) -> None:
        stack = ScoringStack(variant="B")
        scored = stack.score(_fset("s1", 0.7))
        # both exist independently; neither equals the other by construction
        assert scored.risk_score is not None
        assert scored.confidence_score is None or scored.confidence_score != scored.risk_score

    def test_severity_from_full_inputs(self) -> None:
        stack = ScoringStack(variant="B")
        quiet = stack.score(_fset("s-q", 0.05))
        loud = stack.score(_fset("s-l", 0.95))
        assert quiet.severity in (FindingSeverity.LOW.value, FindingSeverity.MEDIUM.value)
        assert loud.severity in (FindingSeverity.HIGH.value, FindingSeverity.CRITICAL.value)

    def test_thin_evidence_lowers_severity(self) -> None:
        stack_thin = ScoringStack(variant="B")
        thin = stack_thin.score(_fset("s-thin", 0.95, quality=0.1))
        rich = ScoringStack(variant="B").score(_fset("s-rich", 0.95, quality=0.9))
        order = ["low", "medium", "high", "critical"]
        assert order.index(thin.severity) <= order.index(rich.severity)

    def test_model_identity_complete(self) -> None:
        stack = ScoringStack(variant="C", baseline_version="bl-abc")
        scored = stack.score(_fset("s1", 0.5))
        identity = scored.as_metadata()
        assert identity["model_name"] == "aegivion.data_exfiltration"
        assert identity["model_version"]
        assert identity["feature_version"].startswith("ml-features-")
        assert identity["baseline_version"] == "bl-abc"
        assert identity["scoring_version"].startswith("scoring-")

    def test_deterministic_scoring(self) -> None:
        rows = [[0.1] * 17] * 30
        model = IsolationForest(n_estimators=20, max_samples=16, seed=42).fit(rows)
        s1 = ScoringStack(variant="C", anomaly_model=model).score(_fset("s1", 0.5))
        s2 = ScoringStack(variant="C", anomaly_model=model).score(_fset("s1", 0.5))
        assert s1.risk_score == s2.risk_score
        assert s1.anomaly_score == s2.anomaly_score


class TestScoredFinding:
    def test_scored_finding_carries_model_and_risk(self) -> None:
        from algo.data_exfiltration.data_exfiltration.finding import build_scored_finding
        from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
        from algo.data_exfiltration.data_exfiltration.session import SessionBuilder
        from .fixtures.cloudtrail_records import S3_GET

        event = EventNormalizer().normalize_cloudtrail(S3_GET)
        builder = SessionBuilder()
        builder.add_events([event])
        (session,) = builder.flush()

        stack = ScoringStack(variant="B", baseline_version="bl-abc")
        scored = stack.score(_fset(session.session_id, 0.85))
        finding = build_scored_finding(session, scored)

        assert finding.risk_score == scored.risk_score
        assert finding.model["model_name"] == "aegivion.data_exfiltration"
        assert finding.model["variant"] == "B"
        assert finding.metadata["scoring"]["fired_rules"] is not None
        assert finding.severity is not None
