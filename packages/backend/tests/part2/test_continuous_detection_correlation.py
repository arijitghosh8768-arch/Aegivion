import pytest
from datetime import datetime, timezone, timedelta
import uuid

from security.engine.detection_context import DetectionContext
from security.engine.detection_correlation import DetectionCorrelationEngine, CorrelationState
from security.engine.agent_controller import AgentEvent, EventSource

def test_context_tenant_isolation():
    ctx = DetectionContext(max_events_per_tenant=10)
    
    e1 = {"event_id": "1", "actor_id": "u1", "occurred_at": datetime.now(timezone.utc)}
    e2 = {"event_id": "2", "actor_id": "u2", "occurred_at": datetime.now(timezone.utc)}
    
    ctx.add_event("org1", e1)
    ctx.add_event("org2", e2)
    
    assert len(ctx._get_tenant("org1").events) == 1
    assert len(ctx._get_tenant("org2").events) == 1

def test_context_bounded_memory():
    ctx = DetectionContext(max_events_per_tenant=5)
    for i in range(10):
        e = {"event_id": str(i), "occurred_at": datetime.now(timezone.utc)}
        ctx.add_event("org1", e)
        
    tenant = ctx._get_tenant("org1")
    assert len(tenant.events) == 5
    assert tenant.events[-1]["event_id"] == "9"
    assert tenant.events[0]["event_id"] == "5"

def test_duplicate_event_handling():
    ctx = DetectionContext()
    e1 = {"event_id": "1", "occurred_at": datetime.now(timezone.utc)}
    
    assert ctx.add_event("org1", e1) == True
    assert ctx.add_event("org1", e1) == False
    
    tenant = ctx._get_tenant("org1")
    assert len(tenant.events) == 1

def test_old_event_expires():
    ctx = DetectionContext(max_window_minutes=60)
    
    old_time = datetime.now(timezone.utc) - timedelta(minutes=61)
    e1 = {"event_id": "1", "occurred_at": old_time}
    
    ctx.add_event("org1", e1)
    # The event is added, but it might be immediately evicted or not added. 
    # Our logic adds then evicts.
    tenant = ctx._get_tenant("org1")
    assert len(tenant.events) == 0

def test_event_ordering():
    ctx = DetectionContext()
    
    t1 = datetime.now(timezone.utc) - timedelta(minutes=5)
    t2 = datetime.now(timezone.utc) - timedelta(minutes=3)
    t3 = datetime.now(timezone.utc) - timedelta(minutes=10)
    
    e1 = {"event_id": "1", "occurred_at": t1}
    e2 = {"event_id": "2", "occurred_at": t2}
    e3 = {"event_id": "3", "occurred_at": t3}
    
    ctx.add_event("org1", e1)
    ctx.add_event("org1", e2)
    ctx.add_event("org1", e3)
    
    tenant = ctx._get_tenant("org1")
    assert tenant.events[0]["event_id"] == "3"
    assert tenant.events[1]["event_id"] == "1"
    assert tenant.events[2]["event_id"] == "2"

def test_correlation_engine_basic():
    engine = DetectionCorrelationEngine()
    
    d1 = {
        "detection_id": "d1", 
        "event_id": "e1", 
        "attack_type": "Credential compromise", 
        "actor_id": "u1",
        "timestamp": datetime.now(timezone.utc)
    }
    
    d2 = {
        "detection_id": "d2", 
        "event_id": "e2", 
        "attack_type": "Data exfiltration", 
        "actor_id": "u1",
        "timestamp": datetime.now(timezone.utc)
    }
    
    res = engine.correlate("org1", d2, [d1])
    assert res is not None
    assert res.correlation_type == "CREDENTIAL_TO_EXFILTRATION"
    assert "d1" in res.detection_ids
    assert "d2" in res.detection_ids
    assert "u1" in res.actor_ids
    assert res.score >= 0.60
    
def test_unrelated_events_do_not_correlate():
    engine = DetectionCorrelationEngine()
    
    d1 = {
        "detection_id": "d1", 
        "event_id": "e1", 
        "attack_type": "Random noise", 
        "actor_id": "u1"
    }
    
    d2 = {
        "detection_id": "d2", 
        "event_id": "e2", 
        "attack_type": "Random noise", 
        "actor_id": "u2"
    }
    
    res = engine.correlate("org1", d2, [d1])
    if res:
        # If it correlates, score must be low
        assert res.score < 0.40
    else:
        assert res is None
