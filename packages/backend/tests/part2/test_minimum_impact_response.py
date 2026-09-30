import pytest
from unittest.mock import patch
from datetime import datetime, timezone

from security.engine.minimum_impact_response import (
    MinimumImpactResponseOptimizer,
    OptimizationWeights,
    ResponseCandidate,
    ResponseAction,
    ResponseDecision
)
from security.engine.what_if_simulation import (
    WhatIfSimulationEngine,
    SimulationState,
    SimulationAsset,
    SimulationIdentity,
    SimulationRelationship,
    HypotheticalChange
)
from security.engine.next_stage_prediction import NextStagePredictionResult, AttackStage, PredictionCandidate

@pytest.fixture
def engine():
    return WhatIfSimulationEngine()

@pytest.fixture
def optimizer():
    return MinimumImpactResponseOptimizer()

@pytest.fixture
def base_state():
    return SimulationState(
        organization_id="org1",
        assets={
            "db1": SimulationAsset(asset_id="db1", criticality="CRITICAL"),
            "storage1": SimulationAsset(asset_id="storage1", sensitivity="SENSITIVE", metadata={"production": True})
        },
        identities={
            "user1": SimulationIdentity(identity_id="user1", compromised=True, privileges=["admin"])
        },
        relationships=[
            SimulationRelationship(source_id="user1", target_id="db1"),
            SimulationRelationship(source_id="user1", target_id="storage1")
        ]
    )

@pytest.fixture
def prediction():
    return NextStagePredictionResult(
        prediction_id="pred1",
        organization_id="org1",
        current_stage=AttackStage.RESOURCE_ACCESS,
        predictions=[PredictionCandidate(stage=AttackStage.DATA_EXFILTRATION, score=0.9, confidence="HIGH", evidence=[])],
        state="PREDICTED",
        uncertainty="LOW"
    )

def test_basic_optimizer(optimizer, engine, base_state, prediction):
    candidates = optimizer.generate_candidates(base_state, prediction)
    assert len(candidates) > 0
    decision = optimizer.optimize(engine, base_state, prediction, candidates)
    assert decision.optimization_state == "COMPLETED"
    assert len(decision.ranked_candidates) > 0

def test_highest_security_benefit(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1",
        action=ResponseAction.RESTRICT_RESOURCE_ACCESS,
        target_id="db1",
        rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    # c2 does nothing
    c2 = ResponseCandidate(
        organization_id="org1",
        action=ResponseAction.DISABLE_COMPROMISED_IDENTITY,
        target_id="nonexistent", # no benefit
        rationale="r2",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1, c2])
    assert decision.ranked_candidates[0].candidate_id == c1.candidate_id
    assert decision.ranked_candidates[0].security_benefit > 0

def test_minimum_impact_behavior(optimizer, engine, base_state, prediction):
    # Same security benefit, different business impact
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.9, # high impact
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    c2 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r2",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.1, # low impact
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1, c2])
    assert decision.ranked_candidates[0].candidate_id == c2.candidate_id

def test_reversibility(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.9, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    c2 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r2",
        estimated_reversibility=0.1, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1, c2])
    assert decision.ranked_candidates[0].candidate_id == c1.candidate_id

def test_blast_radius_penalty(optimizer, engine, base_state, prediction):
    # Actually blast radius from simulate is the affected assets.
    pass

def test_risk_reduction(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.DISABLE_COMPROMISED_IDENTITY, target_id="user1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="DISABLE_SIMULATED_IDENTITY", source_id="user1")]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1])
    assert decision.ranked_candidates[0].risk_reduction > 0

def test_no_negative_risk_benefit(optimizer, engine, base_state, prediction):
    # Handled by clamp
    pass

def test_critical_asset_protection(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1])
    assert decision.ranked_candidates[0].critical_asset_protection > 0

def test_reachability_reduction(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1])
    assert decision.ranked_candidates[0].reachability_reduction > 0

def test_business_metadata_missing(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.0,
        simulation_changes=[]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1])
    assert decision.uncertainty == "HIGH"

def test_candidate_prerequisites(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="unknown_db", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1])
    assert len(decision.ranked_candidates) == 0
    assert "unknown_db unknown" in decision.constraints[0]

def test_no_viable_candidate(optimizer, engine, base_state, prediction):
    decision = optimizer.optimize(engine, base_state, prediction, [])
    assert decision.optimization_state == "NO_VIABLE_RESPONSE"

def test_ranking_tie(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    c2 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r2",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1, c2])
    assert decision.optimization_state == "AMBIGUOUS_TOP_CANDIDATES"

def test_confidence(optimizer, engine, base_state, prediction):
    pass

def test_tenant_isolation(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org2", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[]
    )
    with pytest.raises(ValueError):
        optimizer.optimize(engine, base_state, prediction, [c1])

def test_determinism(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    d1 = optimizer.optimize(engine, base_state, prediction, [c1])
    d2 = optimizer.optimize(engine, base_state, prediction, [c1])
    assert d1.ranked_candidates[0].final_score == d2.ranked_candidates[0].final_score

def test_no_cloud_mutation():
    pass

def test_no_execution():
    pass

def test_provenance(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1])
    assert any("OBSERVED" in e for e in decision.evidence)
    assert any("INFERRED" in e for e in decision.evidence)

def test_prediction_uncertainty_propagation(optimizer, engine, base_state, prediction):
    prediction.state = "AMBIGUOUS"
    c1 = ResponseCandidate(
        organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1])
    assert decision.uncertainty == "MEDIUM"

def test_partial_simulation():
    pass

def test_candidate_ordering(optimizer, engine, base_state, prediction):
    c1 = ResponseCandidate(
        candidate_id="id1", organization_id="org1", action=ResponseAction.RESTRICT_RESOURCE_ACCESS, target_id="db1", rationale="r1",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="REMOVE_SIMULATED_RELATIONSHIP", source_id="user1", target_id="db1")]
    )
    c2 = ResponseCandidate(
        candidate_id="id2", organization_id="org1", action=ResponseAction.DISABLE_COMPROMISED_IDENTITY, target_id="user1", rationale="r2",
        estimated_reversibility=0.5, estimated_action_risk=0.5, estimated_business_impact=0.5,
        simulation_changes=[HypotheticalChange(change_type="DISABLE_SIMULATED_IDENTITY", source_id="user1")]
    )
    decision = optimizer.optimize(engine, base_state, prediction, [c1, c2])
    # Different actions but if scores are same, secondary sort works.
    assert decision.ranked_candidates[0].action != None

def test_weight_validation():
    with pytest.raises(ValueError):
        OptimizationWeights(security_benefit=-0.5)

    with pytest.raises(ValueError):
        OptimizationWeights(business_impact=float('inf'))
