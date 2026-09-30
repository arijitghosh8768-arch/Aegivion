import pytest
from datetime import datetime, timezone

from security.engine.attack_state_tracker import SecurityAttackStateTracker, AttackState
from security.engine.agent_workers import ActivationRiskWorker
from security.engine.agent_controller import AgentEvent, EventSource

def test_state_tracker_basic_escalation():
    tracker = SecurityAttackStateTracker()
    
    # 1. Low scores -> NO_ACTIVITY or POTENTIAL
    ctx = tracker.update_state("org1", "seq1", 0.05, 0.05, 0.05, [])
    assert ctx.current_state in [AttackState.NO_ACTIVITY, AttackState.POTENTIAL]
    
    # 2. Medium scores -> ACTIVATING
    ctx = tracker.update_state("org1", "seq1", 0.6, 0.6, 0.4, [])
    assert ctx.current_state == AttackState.ACTIVATING
    assert len(ctx.transitions) >= 1
    
    # 3. High activation -> ACTIVE
    ctx = tracker.update_state("org1", "seq1", 0.9, 0.9, 0.9, [])
    assert ctx.current_state == AttackState.ACTIVE
    
    # 4. Try lower scores -> shouldn't downgrade automatically
    ctx = tracker.update_state("org1", "seq1", 0.1, 0.1, 0.1, [])
    assert ctx.current_state == AttackState.ACTIVE

def test_state_tracker_manual_resolution():
    tracker = SecurityAttackStateTracker()
    ctx = tracker.update_state("org1", "seq2", 0.9, 0.9, 0.9, [])
    assert ctx.current_state == AttackState.ACTIVE
    
    tracker.mark_contained("org1", "seq2", "Isolated host")
    ctx = tracker.get_context("org1", "seq2")
    assert ctx.current_state == AttackState.CONTAINED
    
    # Update state should not escalate a contained attack
    ctx = tracker.update_state("org1", "seq2", 0.9, 0.9, 0.9, [])
    assert ctx.current_state == AttackState.CONTAINED

@pytest.mark.asyncio
async def test_activation_risk_worker_integration():
    worker = ActivationRiskWorker("w1", "org1")
    
    # Mock event
    evt = AgentEvent(
        event_id="e1",
        organization_id="org1",
        event_type="DETECTION_COMPLETED",
        occurred_at=datetime.now(timezone.utc),
        source=EventSource.DETECTION,
        correlation_id="corr1",
        payload={
            "security_event_id": "se1",
            "detections": [
                {"attack_type": "Credential compromise", "confidence_score": 0.8}
            ]
        },
        provenance=[]
    )
    
    emitted = []
    async def mock_emit(e):
        emitted.append(e)
        
    worker.emit = mock_emit
    
    await worker.process_event(evt)
    
    assert len(emitted) == 1
    out = emitted[0]
    assert out.event_type == "ACTIVATION_ANALYSIS_COMPLETED"
    
    payload = out.payload
    assert "attack_state" in payload
    assert payload["attack_state"] in [s.value for s in AttackState]
    assert "temporal" in payload
    assert "path_risk" in payload
    assert "unified" in payload
    assert "prediction" in payload
