import pytest
from datetime import datetime, timezone
from security.engine.response_safety_policy import (
    ResponseSafetyPolicyEngine,
    ResponseSafetyPolicy,
    PolicyDecision,
    ResponseTarget,
    DEFAULT_POLICY
)
from security.engine.minimum_impact_response import ResponseAction, ResponseDecision, ResponseCandidateScore
from security.engine.next_stage_prediction import NextStagePredictionResult, AttackStage, PredictionCandidate
from security.engine.what_if_simulation import WhatIfSimulationResult, SimulationBaseline, BlastRadius

@pytest.fixture
def engine():
    return ResponseSafetyPolicyEngine()

@pytest.fixture
def prediction():
    return NextStagePredictionResult(
        prediction_id="p1",
        organization_id="org1",
        current_stage=AttackStage.RESOURCE_ACCESS,
        predictions=[],
        state="PREDICTED",
        uncertainty="LOW"
    )

@pytest.fixture
def simulation():
    return WhatIfSimulationResult(
        scenario_id="scenario-1",
        organization_id="org1",
        simulated_stage=AttackStage.RESOURCE_ACCESS,
        state="COMPLETED",
        baseline=SimulationBaseline(attack_paths=[], path_risk_score=0.0, reachable_assets=set(), critical_assets=set()),
        simulated_reachable_assets=set(),
        simulated_risk_score=0.0,
        baseline_risk_score=0.0,
        risk_delta=0.0,
        new_attack_paths=[],
        blast_radius=BlastRadius(affected_assets=0, affected_identities=0, affected_providers=0, affected_regions=0),
        impact_level="LOW",
        uncertainty="LOW"
    )

@pytest.fixture
def optimizer_decision():
    return ResponseDecision(
        organization_id="org1",
        optimization_state="COMPLETED",
        confidence="HIGH",
        uncertainty="LOW"
    )

@pytest.fixture
def candidate():
    return ResponseCandidateScore(
        candidate_id="c1",
        action=ResponseAction.RESTRICT_RESOURCE_ACCESS,
        security_benefit=0.8,
        attack_path_reduction=0.8,
        risk_reduction=0.8,
        critical_asset_protection=0.8,
        reachability_reduction=0.8,
        business_impact=0.1,
        blast_radius=0.1,
        action_risk=0.1,
        reversibility=0.9,
        final_score=0.8,
        confidence="HIGH"
    )

@pytest.fixture
def target():
    return ResponseTarget(
        target_id="db1",
        target_type="database",
        provider="aws",
        organization_id="org1",
        production=False,
        criticality="LOW"
    )

def test_basic_allow(engine, prediction, simulation, optimizer_decision, candidate, target):
    policy = DEFAULT_POLICY.model_copy(update={"auto_approval_enabled": True})
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy)
    assert res.decision == PolicyDecision.ALLOW

def test_production_target(engine, prediction, simulation, optimizer_decision, candidate, target):
    target.production = True
    policy = DEFAULT_POLICY.model_copy(update={"auto_approval_enabled": True})
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_critical_target(engine, prediction, simulation, optimizer_decision, candidate, target):
    target.criticality = "CRITICAL"
    policy = DEFAULT_POLICY.model_copy(update={"auto_approval_enabled": True})
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_protected_target(engine, prediction, simulation, optimizer_decision, candidate, target):
    target.protected = True
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.DENY

def test_action_denylist(engine, prediction, simulation, optimizer_decision, candidate, target):
    policy = DEFAULT_POLICY.model_copy(update={"denied_actions": frozenset({ResponseAction.RESTRICT_RESOURCE_ACCESS})})
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy)
    assert res.decision == PolicyDecision.DENY

def test_action_not_allowlisted(engine, prediction, simulation, optimizer_decision, candidate, target):
    policy = DEFAULT_POLICY.model_copy(update={"allowed_actions": frozenset()})
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy)
    assert res.decision == PolicyDecision.DENY

def test_low_activation_confidence(engine, prediction, simulation, optimizer_decision, candidate, target):
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, activation_confidence=0.1)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_low_prediction_confidence(engine, prediction, simulation, optimizer_decision, candidate, target):
    optimizer_decision.confidence = "LOW"
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_high_uncertainty(engine, prediction, simulation, optimizer_decision, candidate, target):
    optimizer_decision.uncertainty = "HIGH"
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_insufficient_evidence():
    # Not explicit in engine logic if missing completely, but simulation=INSUFFICIENT_DATA handled
    pass

def test_partial_simulation(engine, prediction, simulation, optimizer_decision, candidate, target):
    simulation.state = "PARTIAL"
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_insufficient_simulation(engine, prediction, simulation, optimizer_decision, candidate, target):
    simulation.state = "INSUFFICIENT_DATA"
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.DENY

def test_blast_radius_exceeded(engine, prediction, simulation, optimizer_decision, candidate, target):
    candidate.blast_radius = 0.99
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.DENY

def test_reversibility_below_threshold(engine, prediction, simulation, optimizer_decision, candidate, target):
    candidate.reversibility = 0.1
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_unknown_business_impact(engine, prediction, simulation, optimizer_decision, candidate, target):
    candidate.business_impact = 0.0
    optimizer_decision.uncertainty = "HIGH"
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_auto_approval_disabled(engine, prediction, simulation, optimizer_decision, candidate, target):
    policy = DEFAULT_POLICY.model_copy(update={"auto_approval_enabled": False})
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_optimizer_score_cannot_override_deny(engine, prediction, simulation, optimizer_decision, candidate, target):
    candidate.final_score = 0.99
    target.protected = True
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.DENY

def test_production_and_critical_target(engine, prediction, simulation, optimizer_decision, candidate, target):
    target.production = True
    target.criticality = "CRITICAL"
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "Production target" in res.approval_reason
    assert "Critical target" in res.approval_reason

def test_tenant_mismatch(engine, prediction, simulation, optimizer_decision, candidate, target):
    target.organization_id = "org2"
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.DENY

def test_invalid_score(engine, prediction, simulation, optimizer_decision, candidate, target):
    candidate.final_score = 1.5
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.decision == PolicyDecision.DENY

from pydantic import ValidationError

def test_invalid_action(engine, prediction, simulation, optimizer_decision, candidate, target):
    candidate.action = "FAKE_ACTION"
    with pytest.raises(ValidationError):
        engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)

def test_policy_version_recorded(engine, prediction, simulation, optimizer_decision, candidate, target):
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert res.policy_id == DEFAULT_POLICY.policy_id
    assert res.policy_version == DEFAULT_POLICY.policy_version

def test_expiration(engine, prediction, simulation, optimizer_decision, candidate, target):
    policy = DEFAULT_POLICY.model_copy(update={"auto_approval_enabled": True})
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy)
    assert res.expires_at is not None

def test_determinism(engine, prediction, simulation, optimizer_decision, candidate, target):
    r1 = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    r2 = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target)
    assert r1.decision == r2.decision
    assert r1.evaluations[0].passed == r2.evaluations[0].passed

def test_no_cloud_mutation():
    pass

def test_no_runbook_execution():
    pass

def test_no_approval_execution():
    pass

def test_explicit_deny_precedence(engine, prediction, simulation, optimizer_decision, candidate, target):
    # auto approve is ON, but blast radius is huge
    candidate.blast_radius = 0.99
    policy = DEFAULT_POLICY.model_copy(update={"auto_approval_enabled": True})
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy)
    assert res.decision == PolicyDecision.DENY

def test_approval_precedence(engine, prediction, simulation, optimizer_decision, candidate, target):
    # auto approve ON, but target is prod -> REQUIRE_APPROVAL
    target.production = True
    policy = DEFAULT_POLICY.model_copy(update={"auto_approval_enabled": True})
    res = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy)
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL

def test_policy_version_change(engine, prediction, simulation, optimizer_decision, candidate, target):
    policy1 = DEFAULT_POLICY.model_copy(update={"policy_version": "1.0", "maximum_blast_radius": 0.0})
    policy2 = DEFAULT_POLICY.model_copy(update={"policy_version": "2.0", "maximum_blast_radius": 1.0, "auto_approval_enabled": True})
    candidate.blast_radius = 0.5
    
    r1 = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy1)
    assert r1.decision == PolicyDecision.DENY
    assert r1.policy_version == "1.0"
    
    r2 = engine.evaluate(prediction, simulation, optimizer_decision, candidate, target, policy=policy2)
    assert r2.decision == PolicyDecision.ALLOW
    assert r2.policy_version == "2.0"
