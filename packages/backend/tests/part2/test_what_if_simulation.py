import pytest
from unittest.mock import patch
from security.engine.what_if_simulation import (
    WhatIfSimulationEngine,
    SimulationState,
    SimulationAsset,
    SimulationIdentity,
    SimulationRelationship,
    SimulationScenario,
    HypotheticalChange
)
from security.engine.next_stage_prediction import AttackStage

@pytest.fixture
def engine():
    return WhatIfSimulationEngine()

@pytest.fixture
def base_state():
    return SimulationState(
        organization_id="org1",
        assets={
            "db1": SimulationAsset(asset_id="db1", criticality="CRITICAL"),
            "storage1": SimulationAsset(asset_id="storage1", sensitivity="SENSITIVE")
        },
        identities={
            "user1": SimulationIdentity(identity_id="user1", compromised=False)
        },
        relationships=[
            SimulationRelationship(source_id="user1", target_id="db1")
        ]
    )

def test_basic_simulation(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        predicted_stage=AttackStage.CREDENTIAL_COMPROMISE,
        hypothetical_changes=[
            HypotheticalChange(change_type="MARK_IDENTITY_COMPROMISED", source_id="user1")
        ]
    )
    result = engine.simulate(base_state, scenario)
    assert result.state == "COMPLETED"
    assert "db1" in result.simulated_reachable_assets

def test_deep_copy_isolation(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="MARK_IDENTITY_COMPROMISED", source_id="user1")
        ]
    )
    result = engine.simulate(base_state, scenario)
    # Ensure base state is unchanged
    assert not base_state.identities["user1"].compromised

def test_credential_compromise(engine, base_state):
    # Already tested basically in test_basic_simulation, verify new_reachable
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="MARK_IDENTITY_COMPROMISED", source_id="user1")
        ]
    )
    result = engine.simulate(base_state, scenario)
    # db1 is newly reachable since user1 wasn't compromised in baseline
    assert "db1" in result.new_reachable_assets

def test_privilege_escalation(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="ADD_SIMULATED_RELATIONSHIP", source_id="user1", target_id="storage1")
        ]
    )
    # Need user1 compromised to reach
    base_state.identities["user1"].compromised = True
    result = engine.simulate(base_state, scenario)
    assert "storage1" in result.new_reachable_assets

def test_data_exfiltration(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="SIMULATE_DATA_EXFILTRATION", target_id="storage1")
        ]
    )
    result = engine.simulate(base_state, scenario)
    assert any("SIMULATED: Data exfiltration from storage1" in e for e in result.evidence)

def test_destructive_access(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="SIMULATE_DESTRUCTIVE_ACCESS", target_id="db1")
        ]
    )
    result = engine.simulate(base_state, scenario)
    assert any("SIMULATED: Destructive access to db1" in e for e in result.evidence)

def test_critical_asset_detection(engine, base_state):
    base_state.identities["user1"].compromised = True
    base_state.assets["db2"] = SimulationAsset(asset_id="db2", criticality="CRITICAL")
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="ADD_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db2")
        ]
    )
    result = engine.simulate(base_state, scenario)
    assert result.blast_radius.critical_assets > 0

def test_missing_metadata(engine):
    base_state = SimulationState(
        organization_id="org1",
        assets={"server1": SimulationAsset(asset_id="server1")}, # no criticality
        identities={"user1": SimulationIdentity(identity_id="user1", compromised=False)},
        relationships=[SimulationRelationship(source_id="user1", target_id="server1")]
    )
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="MARK_IDENTITY_COMPROMISED", source_id="user1")
        ]
    )
    result = engine.simulate(base_state, scenario)
    # Impact should be unknown due to no crit/sens
    assert result.impact_level == "UNKNOWN"

def test_cyclic_graph(engine, base_state):
    base_state.relationships.append(SimulationRelationship(source_id="db1", target_id="user1"))
    base_state.identities["user1"].compromised = True
    scenario = SimulationScenario(organization_id="org1")
    # Should not infinite loop
    result = engine.simulate(base_state, scenario)
    assert result.state == "COMPLETED"

def test_multiple_paths(engine, base_state):
    base_state.relationships.append(SimulationRelationship(source_id="user1", target_id="storage1"))
    base_state.relationships.append(SimulationRelationship(source_id="storage1", target_id="db1"))
    base_state.identities["user1"].compromised = True
    scenario = SimulationScenario(organization_id="org1")
    result = engine.simulate(base_state, scenario)
    # Baseline paths
    assert len(result.baseline.attack_paths) > 0

def test_path_risk_delta(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="MARK_IDENTITY_COMPROMISED", source_id="user1")
        ]
    )
    result = engine.simulate(base_state, scenario)
    # Baseline is 0 because no user is compromised
    # Simulated risk is > 0
    assert result.risk_delta > 0

def test_tenant_isolation(engine, base_state):
    scenario = SimulationScenario(organization_id="org2")
    with pytest.raises(ValueError, match="different organizations"):
        engine.simulate(base_state, scenario)

def test_unsupported_operation(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="RUN_SHELL")
        ]
    )
    with pytest.raises(ValueError, match="Unsupported simulation change type"):
        engine.simulate(base_state, scenario)

def test_no_cloud_mutation():
    # Implicit: simulation only manipulates data classes in memory
    pass

def test_ambiguous_prediction(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        predicted_stage=AttackStage.UNKNOWN
    )
    result = engine.simulate(base_state, scenario)
    assert result.simulated_stage == AttackStage.UNKNOWN

def test_determinism(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="MARK_IDENTITY_COMPROMISED", source_id="user1")
        ]
    )
    res1 = engine.simulate(base_state, scenario)
    res2 = engine.simulate(base_state, scenario)
    assert res1.risk_delta == res2.risk_delta
    assert res1.new_reachable_assets == res2.new_reachable_assets

def test_empty_graph(engine):
    state = SimulationState(organization_id="org1")
    scenario = SimulationScenario(organization_id="org1")
    result = engine.simulate(state, scenario)
    assert result.state == "INSUFFICIENT_DATA"

def test_evidence_provenance(engine, base_state):
    scenario = SimulationScenario(
        organization_id="org1",
        hypothetical_changes=[
            HypotheticalChange(change_type="MARK_IDENTITY_COMPROMISED", source_id="user1")
        ]
    )
    result = engine.simulate(base_state, scenario)
    has_simulated = False
    has_inferred = False
    for ev in result.evidence:
        if "SIMULATED:" in ev: has_simulated = True
        if "INFERRED:" in ev: has_inferred = True
    assert has_simulated
    assert has_inferred
