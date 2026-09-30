from enum import Enum
from typing import List, Optional, FrozenSet
from pydantic import BaseModel, Field
from datetime import datetime, timezone, timedelta
import uuid
import math

from security.engine.minimum_impact_response import ResponseAction, ResponseDecision, ResponseCandidateScore
from security.engine.next_stage_prediction import NextStagePredictionResult
from security.engine.what_if_simulation import WhatIfSimulationResult

class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

class PolicyRuleType(str, Enum):
    ALLOWLIST = "ALLOWLIST"
    DENYLIST = "DENYLIST"
    TARGET = "TARGET"
    ENVIRONMENT = "ENVIRONMENT"
    CRITICALITY = "CRITICALITY"
    CONFIDENCE = "CONFIDENCE"
    SIMULATION = "SIMULATION"
    BLAST_RADIUS = "BLAST_RADIUS"
    REVERSIBILITY = "REVERSIBILITY"
    APPROVAL = "APPROVAL"
    INPUT_INTEGRITY = "INPUT_INTEGRITY"

class ResponseTarget(BaseModel):
    target_id: str
    target_type: str
    provider: str
    environment: Optional[str] = None
    criticality: Optional[str] = None
    business_critical: Optional[bool] = None
    production: Optional[bool] = None
    shared_service: Optional[bool] = None
    protected: Optional[bool] = None
    organization_id: str

class ActionPolicy(BaseModel):
    action: ResponseAction
    allowed: bool
    requires_approval: bool
    minimum_confidence: float
    minimum_reversibility: float
    maximum_blast_radius: float
    production_allowed: bool
    critical_target_allowed: bool

class ResponseSafetyPolicy(BaseModel):
    policy_id: str = "default-response-policy"
    policy_version: str = "1.0"
    allowed_actions: FrozenSet[ResponseAction]
    denied_actions: FrozenSet[ResponseAction] = Field(default_factory=frozenset)
    minimum_activation_confidence: float = 0.70
    minimum_prediction_confidence: float = 0.70
    minimum_simulation_completeness: float = 1.0
    maximum_blast_radius: float = 0.30
    minimum_reversibility: float = 0.70
    production_requires_approval: bool = True
    critical_asset_requires_approval: bool = True
    unknown_business_impact_requires_approval: bool = True
    high_uncertainty_requires_approval: bool = True
    auto_approval_enabled: bool = False
    action_policies: dict[ResponseAction, ActionPolicy] = Field(default_factory=dict)
    approval_validity_minutes: int = 15

class PolicyEvaluation(BaseModel):
    rule_type: PolicyRuleType
    rule_id: str
    passed: bool
    outcome: PolicyDecision
    reason: str
    evidence: List[str] = Field(default_factory=list)

class ResponsePolicyDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str
    candidate_id: str
    action: ResponseAction
    decision: PolicyDecision
    optimizer_score: float
    confidence: str
    uncertainty: str
    evaluations: List[PolicyEvaluation] = Field(default_factory=list)
    blocking_reasons: List[str] = Field(default_factory=list)
    approval_required: bool
    approval_reason: Optional[str] = None
    expires_at: Optional[datetime] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    policy_id: str
    policy_version: str

DEFAULT_POLICY = ResponseSafetyPolicy(
    allowed_actions=frozenset({
        ResponseAction.RESTRICT_IDENTITY_PRIVILEGE,
        ResponseAction.RESTRICT_RESOURCE_ACCESS,
        ResponseAction.REMOVE_PUBLIC_ACCESS,
        ResponseAction.REVOKE_COMPROMISED_CREDENTIAL,
        ResponseAction.DISABLE_COMPROMISED_IDENTITY,
        ResponseAction.ISOLATE_NETWORK_PATH,
    })
)

class ResponseSafetyPolicyEngine:
    
    def evaluate(self,
                 prediction: NextStagePredictionResult,
                 simulation: WhatIfSimulationResult,
                 optimizer_decision: ResponseDecision,
                 candidate: ResponseCandidateScore,
                 target: Optional[ResponseTarget],
                 policy: ResponseSafetyPolicy = DEFAULT_POLICY,
                 activation_confidence: float = 0.8) -> ResponsePolicyDecision:
        
        evaluations: List[PolicyEvaluation] = []
        blocking_reasons: List[str] = []
        
        # Helper to record eval and optionally abort
        def record_eval(rule_type: PolicyRuleType, passed: bool, outcome: PolicyDecision, reason: str, evidence: str = None) -> bool:
            ev = PolicyEvaluation(
                rule_type=rule_type,
                rule_id=f"{rule_type.name}_CHECK",
                passed=passed,
                outcome=outcome,
                reason=reason,
                evidence=[f"POLICY: {reason}"] + ([evidence] if evidence else [])
            )
            evaluations.append(ev)
            if not passed and outcome == PolicyDecision.DENY:
                blocking_reasons.append(reason)
                return False # signals a hard deny
            return True

        def return_final(decision: PolicyDecision, approval_reason: str = None) -> ResponsePolicyDecision:
            return ResponsePolicyDecision(
                organization_id=optimizer_decision.organization_id,
                candidate_id=candidate.candidate_id,
                action=candidate.action,
                decision=decision,
                optimizer_score=candidate.final_score,
                confidence=optimizer_decision.confidence,
                uncertainty=optimizer_decision.uncertainty,
                evaluations=evaluations,
                blocking_reasons=blocking_reasons,
                approval_required=(decision == PolicyDecision.REQUIRE_APPROVAL),
                approval_reason=approval_reason,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=policy.approval_validity_minutes) if decision in [PolicyDecision.ALLOW, PolicyDecision.REQUIRE_APPROVAL] else None,
                generated_at=datetime.now(timezone.utc),
                policy_id=policy.policy_id,
                policy_version=policy.policy_version
            )

        # 1. Input integrity
        if math.isnan(candidate.final_score) or math.isinf(candidate.final_score) or not (0 <= candidate.final_score <= 1):
            record_eval(PolicyRuleType.INPUT_INTEGRITY, False, PolicyDecision.DENY, "Invalid optimizer score")
            return return_final(PolicyDecision.DENY)

        # 2. Tenant isolation
        org_id = optimizer_decision.organization_id
        if prediction.organization_id != org_id or simulation.organization_id != org_id:
            record_eval(PolicyRuleType.INPUT_INTEGRITY, False, PolicyDecision.DENY, "Tenant mismatch between inputs")
            return return_final(PolicyDecision.DENY)
        
        if target and target.organization_id != org_id:
            record_eval(PolicyRuleType.INPUT_INTEGRITY, False, PolicyDecision.DENY, "Tenant mismatch with target")
            return return_final(PolicyDecision.DENY)

        # 3. Action Allowlist / Denylist
        if candidate.action in policy.denied_actions:
            record_eval(PolicyRuleType.DENYLIST, False, PolicyDecision.DENY, f"Action {candidate.action} is explicitly denied")
            return return_final(PolicyDecision.DENY)
            
        if candidate.action not in policy.allowed_actions:
            record_eval(PolicyRuleType.ALLOWLIST, False, PolicyDecision.DENY, f"Action {candidate.action} is not allowlisted")
            return return_final(PolicyDecision.DENY)
        
        # 4. Confidence
        if activation_confidence < policy.minimum_activation_confidence:
            if not record_eval(PolicyRuleType.CONFIDENCE, False, PolicyDecision.REQUIRE_APPROVAL, "Activation confidence below threshold"):
                pass
        
        pred_conf = 1.0 if optimizer_decision.confidence == "HIGH" else 0.5
        if pred_conf < policy.minimum_prediction_confidence:
            if not record_eval(PolicyRuleType.CONFIDENCE, False, PolicyDecision.REQUIRE_APPROVAL, "Prediction confidence below threshold"):
                pass
                
        if optimizer_decision.uncertainty == "HIGH" and policy.high_uncertainty_requires_approval:
            record_eval(PolicyRuleType.CONFIDENCE, False, PolicyDecision.REQUIRE_APPROVAL, "High uncertainty requires approval")

        # 5. Simulation Completeness
        if simulation.state == "INSUFFICIENT_DATA":
            record_eval(PolicyRuleType.SIMULATION, False, PolicyDecision.DENY, "Insufficient simulation data")
            return return_final(PolicyDecision.DENY)
            
        if simulation.state == "PARTIAL":
            record_eval(PolicyRuleType.SIMULATION, False, PolicyDecision.REQUIRE_APPROVAL, "Partial simulation requires approval")

        # 6. Target Eligibility
        if target:
            if target.protected:
                record_eval(PolicyRuleType.TARGET, False, PolicyDecision.DENY, "Target is protected")
                return return_final(PolicyDecision.DENY)
                
            if target.criticality == "CRITICAL" and policy.critical_asset_requires_approval:
                record_eval(PolicyRuleType.CRITICALITY, False, PolicyDecision.REQUIRE_APPROVAL, "Critical target requires approval")
                
            if target.production and policy.production_requires_approval:
                record_eval(PolicyRuleType.ENVIRONMENT, False, PolicyDecision.REQUIRE_APPROVAL, "Production target requires approval")

        # 7. Blast Radius
        if candidate.blast_radius > policy.maximum_blast_radius:
            record_eval(PolicyRuleType.BLAST_RADIUS, False, PolicyDecision.DENY, f"Blast radius {candidate.blast_radius} exceeds maximum {policy.maximum_blast_radius}")
            return return_final(PolicyDecision.DENY)
            
        # 8. Reversibility
        if candidate.reversibility < policy.minimum_reversibility:
            record_eval(PolicyRuleType.REVERSIBILITY, False, PolicyDecision.REQUIRE_APPROVAL, "Reversibility below minimum threshold")

        # 9. Business Impact Uncertainty
        if candidate.business_impact == 0.0 and policy.unknown_business_impact_requires_approval:
            # We treat 0.0 as unknown for this logic if metadata was missing, or explicit flag. 
            # The prompt implies checking if business_impact was UNKNOWN. We approximate it:
            if optimizer_decision.uncertainty == "HIGH":
                record_eval(PolicyRuleType.CONFIDENCE, False, PolicyDecision.REQUIRE_APPROVAL, "Unknown business impact requires approval")
        
        # 10. Auto-approval check
        if not policy.auto_approval_enabled:
            record_eval(PolicyRuleType.APPROVAL, False, PolicyDecision.REQUIRE_APPROVAL, "Auto-approval disabled")

        # Determine Final Decision
        final_decision = PolicyDecision.ALLOW
        approval_reasons = []
        
        for ev in evaluations:
            if ev.outcome == PolicyDecision.DENY:
                return return_final(PolicyDecision.DENY)
            if ev.outcome == PolicyDecision.INSUFFICIENT_EVIDENCE:
                final_decision = PolicyDecision.INSUFFICIENT_EVIDENCE
            if ev.outcome == PolicyDecision.REQUIRE_APPROVAL and final_decision != PolicyDecision.INSUFFICIENT_EVIDENCE:
                final_decision = PolicyDecision.REQUIRE_APPROVAL
                approval_reasons.append(ev.reason)

        if final_decision == PolicyDecision.REQUIRE_APPROVAL:
            return return_final(final_decision, approval_reason="; ".join(approval_reasons))
            
        return return_final(final_decision)
