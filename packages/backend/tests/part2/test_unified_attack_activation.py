import pytest
from datetime import datetime, timezone
from security.engine.unified_attack_activation import UnifiedAttackActivationEngine, ActivationState
from security.engine.detectors.base import DetectionResult
from security.engine.dynamic_attack_path import DynamicAttackPathRiskResult
from security.engine.temporal_attack_progression import TemporalProgressionResult, TemporalProgressionState

@pytest.fixture
def engine():
    return UnifiedAttackActivationEngine()

def _det(score, org="org1"):
    return DetectionResult(
        detector_name="test",
        attack_type="test",
        is_suspicious=score > 0,
        confidence_score=score,
        metadata={"organization_id": org}
    )

def _path(score, org="org1"):
    from security.engine.dynamic_attack_path import RiskLevel
    return DynamicAttackPathRiskResult(
        organization_id=org,
        entry_node="n1",
        target_node="n2",
        path_nodes=["n1", "n2"],
        path_edges=["n1->n2"],
        path_length=1,
        risk_score=score,
        risk_level=RiskLevel.HIGH if score > 0.5 else RiskLevel.LOW,
        node_contributions=[],
        edge_contributions=[],
        dominant_factors=[],
        target_impact=score
    )

def _temp(score, org="org1"):
    return TemporalProgressionResult(
        organization_id=org,
        actor_id="a1",
        ordered_events=[],
        window_minutes=60,
        progression_score=score,
        state=TemporalProgressionState.STRONG_PROGRESSION if score > 0.5 else TemporalProgressionState.NO_SEQUENCE,
        evidence=[]
    )

def test_all_components_low(engine):
    res = engine.evaluate("org1", _det(0.1), _path(0.1), _temp(0.1))
    assert res.state == ActivationState.INACTIVE

def test_high_detector_low_path(engine):
    res = engine.evaluate("org1", _det(0.9), _path(0.05), _temp(0.9))
    assert res.state == ActivationState.POTENTIAL
    assert res.activation_score <= 0.49

def test_high_detector_high_path_no_temporal(engine):
    res = engine.evaluate("org1", _det(0.9), _path(0.9), None)
    assert res.state == ActivationState.ACTIVATING
    assert res.activation_score == 0.79

def test_full_high_confidence(engine):
    res = engine.evaluate("org1", _det(0.9), _path(0.9), _temp(0.9))
    assert res.state == ActivationState.ACTIVE
    assert res.activation_score == 0.90

def test_no_viable_path(engine):
    res = engine.evaluate("org1", _det(0.9), None, _temp(0.9))
    assert res.state == ActivationState.POTENTIAL
    assert res.activation_score <= 0.49

def test_partial_path(engine):
    res = engine.evaluate("org1", _det(0.5), _path(0.4), _temp(0.5))
    assert res.state == ActivationState.POTENTIAL or res.state == ActivationState.ACTIVATING

def test_strong_path_strong_temporal(engine):
    res = engine.evaluate("org1", None, _path(0.9), _temp(0.9))
    assert res.state == ActivationState.ACTIVATING

def test_scores_preserved(engine):
    res = engine.evaluate("org1", _det(0.81), _path(0.82), _temp(0.83))
    assert res.detector_confidence == 0.81
    assert res.path_risk == 0.82
    assert res.temporal_progression_score == 0.83

def test_missing_temporal_graceful(engine):
    res = engine.evaluate("org1", _det(0.5), _path(0.5), None)
    assert res.temporal_progression_score is None
    assert isinstance(res.activation_score, float)

def test_missing_path_graceful(engine):
    res = engine.evaluate("org1", _det(0.5), None, _temp(0.5))
    assert res.path_risk is None
    assert isinstance(res.activation_score, float)

def test_cross_tenant_rejected(engine):
    with pytest.raises(ValueError):
        engine.evaluate("org1", _det(0.9, "org2"), _path(0.9, "org1"), _temp(0.9, "org1"))

def test_determinism(engine):
    res1 = engine.evaluate("org1", _det(0.7), _path(0.7), _temp(0.7))
    res2 = engine.evaluate("org1", _det(0.7), _path(0.7), _temp(0.7))
    assert res1.activation_score == res2.activation_score
    assert res1.activation_id != res2.activation_id

def test_evidence_traceability(engine):
    res = engine.evaluate("org1", _det(0.9), _path(0.9), None)
    factors = [e.factor for e in res.evidence_trace]
    assert "DETECTOR_CONFIDENCE" in factors
    assert "PATH_RISK" in factors
    assert "TEMPORAL_GATING" in factors

def test_legitimate_admin_sequence(engine):
    # Strong temporal, no detector, low path
    res = engine.evaluate("org1", _det(0.0), _path(0.1), _temp(0.9))
    assert res.state == ActivationState.INACTIVE or res.state == ActivationState.POTENTIAL
