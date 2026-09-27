import pytest
from datetime import datetime, timezone
from security.engine.detectors.base import DetectionResult, DetectionEvidence
from security.engine.attack_activation import AttackActivationEngine

class DummyEvent:
    def __init__(self, event_id: str):
        self.event_id = event_id
        self.timestamp = datetime.now(timezone.utc)

@pytest.fixture
def base_detection():
    return DetectionResult(
        detector_name="DummyDetector",
        attack_type="DUMMY_ATTACK",
        is_suspicious=True,
        confidence_score=0.8,
        actor_id="user1",
        affected_resources=["resource1"],
        evidence=[],
        metadata={"detector_version": "1.0"}
    )

@pytest.fixture
def engine():
    return AttackActivationEngine()

def test_no_detection_evidence(engine):
    detection = DetectionResult(
        detector_name="DummyDetector",
        attack_type="DUMMY_ATTACK",
        is_suspicious=False,
        confidence_score=0.1,
        actor_id="user1",
        affected_resources=["resource1"]
    )
    result = engine.evaluate(detection, {"organization_id": "org1"})
    assert result.activation_state == "INACTIVE"
    assert result.activation_score == 0.0

def test_detection_no_viable_path(engine, base_detection):
    # No path -> low activation score
    context = {"organization_id": "org1"}
    result = engine.evaluate(base_detection, context)
    assert result.activation_state == "INACTIVE"
    assert result.activation_score == 0.3 # Base detection bump

def test_detection_with_valid_path(engine, base_detection):
    context = {"organization_id": "org1", "valid_path_exists": True}
    result = engine.evaluate(base_detection, context)
    assert result.activation_score == 0.6 # 0.3 + 0.3
    assert result.activation_state == "ACTIVATING"
    assert len(result.attack_path) == 3

def test_detection_with_privileged_identity(engine, base_detection):
    context = {"organization_id": "org1", "actor_roles": ["admin"]}
    result = engine.evaluate(base_detection, context)
    assert result.activation_score == 0.5 # 0.3 + 0.2
    assert any("PRIVILEGED_ACCESS" == f["factor"] for f in result.contributing_factors)

def test_detection_critical_target(engine, base_detection):
    context = {"organization_id": "org1", "critical_assets": ["resource1"]}
    result = engine.evaluate(base_detection, context)
    assert result.activation_score == 0.5 # 0.3 + 0.2
    assert any("ASSET_CRITICALITY" == f["factor"] for f in result.contributing_factors)

def test_temporal_event_progression(engine, base_detection):
    context = {"organization_id": "org1"}
    events = [DummyEvent("evt-1"), DummyEvent("evt-2")]
    result = engine.evaluate(base_detection, context, event_history=events)
    assert result.activation_score == 0.5 # 0.3 + 0.2
    assert any("TEMPORAL_PROGRESSION" == f["factor"] for f in result.contributing_factors)

def test_partial_path(engine, base_detection):
    context = {"organization_id": "org1", "partial_path_exists": True}
    result = engine.evaluate(base_detection, context)
    assert result.activation_score == 0.4 # 0.3 + 0.1
    assert result.activation_state == "POTENTIAL"

def test_complete_high_risk_path(engine, base_detection):
    context = {
        "organization_id": "org1", 
        "valid_path_exists": True,
        "actor_roles": ["admin"],
        "critical_assets": ["resource1"]
    }
    events = [DummyEvent("evt-1"), DummyEvent("evt-2")]
    result = engine.evaluate(base_detection, context, event_history=events)
    # 0.3 (detection) + 0.2 (privilege) + 0.3 (path) + 0.2 (criticality) + 0.2 (temporal) = 1.2 -> capped to 1.0
    assert result.activation_score == 1.0
    assert result.activation_state == "ACTIVE"
    
def test_missing_identity_relationship(engine):
    detection = DetectionResult(
        detector_name="DummyDetector",
        attack_type="DUMMY_ATTACK",
        is_suspicious=True,
        confidence_score=0.8,
        actor_id=None,
        affected_resources=["resource1"]
    )
    result = engine.evaluate(detection, {"organization_id": "org1"})
    assert result.activation_state == "INSUFFICIENT_EVIDENCE"

def test_missing_asset_criticality(engine, base_detection):
    context = {"organization_id": "org1"} # no critical_assets
    result = engine.evaluate(base_detection, context)
    # Does not crash, handles gracefully
    assert not any("ASSET_CRITICALITY" == f["factor"] for f in result.contributing_factors)

def test_determinism(engine, base_detection):
    context = {"organization_id": "org1", "actor_roles": ["admin"]}
    res1 = engine.evaluate(base_detection, context)
    res2 = engine.evaluate(base_detection, context)
    assert res1.activation_score == res2.activation_score
    assert res1.activation_state == res2.activation_state
    
def test_evidence_traceability(engine, base_detection):
    context = {"organization_id": "org1", "actor_roles": ["admin"]}
    result = engine.evaluate(base_detection, context)
    factors = {f["factor"]: f for f in result.contributing_factors}
    assert "DETECTION_EVIDENCE" in factors
    assert factors["DETECTION_EVIDENCE"]["classification"] == "OBSERVED"
    assert "PRIVILEGED_ACCESS" in factors
    assert factors["PRIVILEGED_ACCESS"]["classification"] == "OBSERVED"

