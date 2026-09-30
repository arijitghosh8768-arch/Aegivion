import pytest
from datetime import datetime, timezone, timedelta
from security.engine.temporal_attack_progression import TemporalAttackProgressionEngine, TemporalProgressionState

@pytest.fixture
def engine():
    return TemporalAttackProgressionEngine()

def test_single_event(engine):
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": datetime.now(timezone.utc)}
    ]
    res = engine.evaluate("org1", events)
    assert res.state == TemporalProgressionState.NO_SEQUENCE

def test_two_unrelated_events_outside_window(engine):
    dt1 = datetime.now(timezone.utc)
    dt2 = dt1 + timedelta(minutes=120)
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": dt1},
        {"event_id": "2", "organization_id": "org1", "timestamp": dt2}
    ]
    res = engine.evaluate("org1", events)
    assert res.state == TemporalProgressionState.NO_SEQUENCE

def test_correct_chronological_sequence(engine):
    dt1 = datetime.now(timezone.utc)
    dt2 = dt1 + timedelta(minutes=5)
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": dt1, "actor": {"id": "act1"}},
        {"event_id": "2", "organization_id": "org1", "timestamp": dt2, "actor": {"id": "act1"}}
    ]
    res = engine.evaluate("org1", events)
    assert res.progression_score > 0
    assert res.state in [TemporalProgressionState.PARTIAL_PROGRESSION, TemporalProgressionState.STRONG_PROGRESSION]

def test_reverse_chronological_sorting(engine):
    dt1 = datetime.now(timezone.utc)
    dt2 = dt1 + timedelta(minutes=5)
    events = [
        {"event_id": "2", "organization_id": "org1", "timestamp": dt2, "actor": {"id": "act1"}},
        {"event_id": "1", "organization_id": "org1", "timestamp": dt1, "actor": {"id": "act1"}}
    ]
    res = engine.evaluate("org1", events)
    assert res.ordered_events == ["1", "2"]

def test_different_actors(engine):
    dt1 = datetime.now(timezone.utc)
    dt2 = dt1 + timedelta(minutes=5)
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": dt1, "actor": {"id": "act1"}},
        {"event_id": "2", "organization_id": "org1", "timestamp": dt2, "actor": {"id": "act2"}}
    ]
    res = engine.evaluate("org1", events)
    # Different actors shouldn't get the actor continuity bonus and we reject progression by default
    assert res.state == TemporalProgressionState.RELATED_EVENTS

def test_same_resource(engine):
    dt1 = datetime.now(timezone.utc)
    dt2 = dt1 + timedelta(minutes=5)
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": dt1, "actor": {"id": "act1"}, "target": {"id": "res1"}},
        {"event_id": "2", "organization_id": "org1", "timestamp": dt2, "actor": {"id": "act1"}, "target": {"id": "res1"}}
    ]
    res = engine.evaluate("org1", events)
    factors = [e.factor for e in res.evidence]
    assert "RESOURCE_CONTINUITY" in factors

def test_missing_timestamp(engine):
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": datetime.now(timezone.utc)},
        {"event_id": "2", "organization_id": "org1"} # missing timestamp
    ]
    res = engine.evaluate("org1", events)
    assert res.state == TemporalProgressionState.INSUFFICIENT_EVIDENCE

def test_duplicate_events(engine):
    dt1 = datetime.now(timezone.utc)
    events = [
        {"event_id": "1", "event_fingerprint": "hash1", "organization_id": "org1", "timestamp": dt1, "actor": {"id": "act1"}},
        {"event_id": "1", "event_fingerprint": "hash1", "organization_id": "org1", "timestamp": dt1, "actor": {"id": "act1"}}
    ]
    res = engine.evaluate("org1", events)
    # Deduplicates to 1 event, which implies NO_SEQUENCE
    assert res.state == TemporalProgressionState.NO_SEQUENCE

def test_credential_privilege_access_sequence(engine):
    dt1 = datetime.now(timezone.utc)
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": dt1, "actor": {"id": "act1"}, "event_type": "LOGIN_FAILURE"},
        {"event_id": "2", "organization_id": "org1", "timestamp": dt1 + timedelta(minutes=1), "actor": {"id": "act1"}, "event_type": "PERMISSION_CHANGED"},
        {"event_id": "3", "organization_id": "org1", "timestamp": dt1 + timedelta(minutes=2), "actor": {"id": "act1"}, "event_type": "OBJECT_READ"}
    ]
    res = engine.evaluate("org1", events)
    assert res.state == TemporalProgressionState.STRONG_PROGRESSION
    assert any(e.factor == "EVENT_COMPATIBILITY" for e in res.evidence)

def test_destruction_sabotage_sequence(engine):
    dt1 = datetime.now(timezone.utc)
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": dt1, "actor": {"id": "act1"}, "event_type": "MASS_DELETE"},
        {"event_id": "2", "organization_id": "org1", "timestamp": dt1 + timedelta(minutes=1), "actor": {"id": "act1"}, "event_type": "BACKUP_DELETED"}
    ]
    res = engine.evaluate("org1", events)
    assert res.state == TemporalProgressionState.STRONG_PROGRESSION

def test_cross_tenant_rejected(engine):
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": datetime.now(timezone.utc)},
        {"event_id": "2", "organization_id": "org2", "timestamp": datetime.now(timezone.utc)}
    ]
    with pytest.raises(ValueError):
        engine.evaluate("org1", events)

def test_determinism(engine):
    dt1 = datetime.now(timezone.utc)
    events = [
        {"event_id": "1", "organization_id": "org1", "timestamp": dt1, "actor": {"id": "act1"}, "event_type": "LOGIN_FAILURE"},
        {"event_id": "2", "organization_id": "org1", "timestamp": dt1 + timedelta(minutes=1), "actor": {"id": "act1"}, "event_type": "PERMISSION_CHANGED"}
    ]
    res1 = engine.evaluate("org1", events)
    res2 = engine.evaluate("org1", events)
    
    assert res1.progression_score == res2.progression_score
    assert res1.progression_id != res2.progression_id
