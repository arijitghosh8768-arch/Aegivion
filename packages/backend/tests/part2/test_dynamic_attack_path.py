import pytest
from security.engine.dynamic_attack_path import DynamicAttackPathRiskEngine

@pytest.fixture
def engine():
    return DynamicAttackPathRiskEngine()

def test_no_path(engine):
    with pytest.raises(ValueError):
        engine.calculate_risk("org1", [], [])

def test_simple_identity_resource_path(engine):
    nodes = [
        {"id": "id-1", "type": "CloudIdentity", "privilege_level": "standard", "risk_score": 0.1},
        {"id": "res-1", "type": "CloudAsset", "criticality": "normal"}
    ]
    edges = [{"source": "id-1", "target": "res-1", "type": "CAN_ACCESS"}]
    
    res = engine.calculate_risk("org1", nodes, edges)
    # Entry risk = 0.1, Edge bump = 0.1, Direct reachability = 0.1, Target criticality = 0.0
    # Score = 0.3 * (0.90) * 1.2 = ~0.32
    assert res.risk_score > 0
    assert res.risk_level == "LOW" or res.risk_level == "MEDIUM"

def test_privileged_identity_higher_risk(engine):
    nodes_std = [
        {"id": "id-1", "type": "CloudIdentity", "privilege_level": "standard", "risk_score": 0.1},
        {"id": "res-1", "type": "CloudAsset"}
    ]
    edges = [{"source": "id-1", "target": "res-1", "type": "CAN_ACCESS"}]
    res_std = engine.calculate_risk("org1", nodes_std, edges)
    
    nodes_admin = [
        {"id": "id-1", "type": "CloudIdentity", "privilege_level": "administrative", "risk_score": 0.1},
        {"id": "res-1", "type": "CloudAsset"}
    ]
    res_admin = engine.calculate_risk("org1", nodes_admin, edges)
    
    assert res_admin.risk_score > res_std.risk_score
    assert "PRIVILEGED_ACCESS" in res_admin.dominant_factors

def test_critical_target_higher_risk(engine):
    nodes_norm = [
        {"id": "id-1", "type": "CloudIdentity", "risk_score": 0.1},
        {"id": "res-1", "type": "CloudAsset", "criticality": "normal"}
    ]
    edges = [{"source": "id-1", "target": "res-1", "type": "CAN_ACCESS"}]
    res_norm = engine.calculate_risk("org1", nodes_norm, edges)
    
    nodes_crit = [
        {"id": "id-1", "type": "CloudIdentity", "risk_score": 0.1},
        {"id": "res-1", "type": "CloudAsset", "criticality": "mission_critical"}
    ]
    res_crit = engine.calculate_risk("org1", nodes_crit, edges)
    
    assert res_crit.risk_score > res_norm.risk_score
    assert "HIGH_TARGET_IMPACT" in res_crit.dominant_factors

def test_read_only_vs_destructive_path(engine):
    nodes_read = [
        {"id": "id-1", "type": "CloudIdentity", "privilege_level": "read", "risk_score": 0.1},
        {"id": "res-1", "type": "CloudAsset"}
    ]
    edges = [{"source": "id-1", "target": "res-1", "type": "CAN_ACCESS"}]
    res_read = engine.calculate_risk("org1", nodes_read, edges)
    
    nodes_write = [
        {"id": "id-1", "type": "CloudIdentity", "privilege_level": "write", "risk_score": 0.1},
        {"id": "res-1", "type": "CloudAsset"}
    ]
    res_write = engine.calculate_risk("org1", nodes_write, edges)
    
    assert res_write.risk_score > res_read.risk_score

def test_direct_path_calculated_correctly(engine):
    nodes = [
        {"id": "id-1", "type": "CloudIdentity"},
        {"id": "res-1", "type": "CloudAsset"}
    ]
    edges = [{"source": "id-1", "target": "res-1", "type": "CAN_ACCESS"}]
    res = engine.calculate_risk("org1", nodes, edges)
    
    assert "DIRECT_REACHABILITY" in res.dominant_factors
    assert res.path_length == 1

def test_multi_hop_path_calculated_correctly(engine):
    nodes = [
        {"id": "id-1", "type": "CloudIdentity"},
        {"id": "res-1", "type": "CloudAsset"},
        {"id": "res-2", "type": "CloudAsset"}
    ]
    edges = [
        {"source": "id-1", "target": "res-1", "type": "CAN_ACCESS"},
        {"source": "res-1", "target": "res-2", "type": "CONNECTED_TO"}
    ]
    res = engine.calculate_risk("org1", nodes, edges)
    
    assert "DIRECT_REACHABILITY" not in res.dominant_factors
    assert res.path_length == 2

def test_relationship_changes_risk_recalculates(engine):
    nodes = [{"id": "id-1", "type": "CloudIdentity"}, {"id": "res-1", "type": "CloudAsset"}]
    edges_weak = [{"source": "id-1", "target": "res-1", "type": "CONNECTED_TO"}]
    edges_strong = [{"source": "id-1", "target": "res-1", "type": "OWNS"}]
    
    res_weak = engine.calculate_risk("org1", nodes, edges_weak)
    res_strong = engine.calculate_risk("org1", nodes, edges_strong)
    assert res_strong.risk_score > res_weak.risk_score

def test_unknown_criticality_handled(engine):
    nodes = [
        {"id": "id-1", "type": "CloudIdentity", "risk_score": 0.1},
        {"id": "res-1", "type": "CloudAsset"} # Missing criticality
    ]
    edges = [{"source": "id-1", "target": "res-1", "type": "CAN_ACCESS"}]
    res = engine.calculate_risk("org1", nodes, edges)
    # Checks that it doesn't crash and returns a valid result
    assert isinstance(res.risk_score, float)

def test_cross_tenant_isolation(engine):
    nodes = [
        {"id": "id-1", "type": "CloudIdentity"},
        {"id": "res-1", "type": "CloudAsset"}
    ]
    edges = [{"source": "id-1", "target": "res-1", "type": "CAN_ACCESS"}]
    res1 = engine.calculate_risk("org1", nodes, edges)
    res2 = engine.calculate_risk("org2", nodes, edges)
    
    assert res1.organization_id == "org1"
    assert res2.organization_id == "org2"

def test_determinism(engine):
    nodes = [
        {"id": "id-1", "type": "CloudIdentity", "privilege_level": "administrative"},
        {"id": "res-1", "type": "CloudAsset", "criticality": "mission_critical"}
    ]
    edges = [{"source": "id-1", "target": "res-1", "type": "OWNS"}]
    
    res1 = engine.calculate_risk("org1", nodes, edges)
    res2 = engine.calculate_risk("org1", nodes, edges)
    
    assert res1.risk_score == res2.risk_score
    assert res1.path_id != res2.path_id  # UUIDs differ but score is identical
    
def test_evidence_traceability(engine):
    nodes = [
        {"id": "id-1", "type": "CloudIdentity", "privilege_level": "administrative"},
        {"id": "res-1", "type": "CloudAsset", "criticality": "mission_critical"}
    ]
    edges = [{"source": "id-1", "target": "res-1", "type": "OWNS"}]
    
    res = engine.calculate_risk("org1", nodes, edges)
    
    node_factors = [c.factor for c in res.node_contributions]
    assert "PRIVILEGED_ACCESS" in node_factors
    assert "TARGET_IMPACT" in node_factors
    
    edge_factors = [c.factor for c in res.edge_contributions]
    assert "RELATIONSHIP_OWNS" in edge_factors
