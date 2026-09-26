from typing import List, Dict, Any, Optional
from security.models.response_candidate_schema import ResponseCandidateSchema, ResponseSafety
from security.models.security_correlation_schema import SecurityCorrelationSchema
from security.models.attack_activation_schema import AttackActivationSchema
from security.models.attack_prediction_schema import AttackPredictionSchema
from security.models.attack_simulation_schema import AttackSimulationSchema

class MinimumImpactResponseEngine:
    """
    Evaluates response candidates to find the one that maximizes risk reduction 
    while minimizing business disruption and blast radius.
    """
    
    @staticmethod
    def evaluate_candidates(
        incident: SecurityCorrelationSchema,
        activation: AttackActivationSchema,
        dynamic_path_risk: Dict[str, Any],
        predictions: List[AttackPredictionSchema],
        simulation: AttackSimulationSchema
    ) -> Dict[str, Any]:
        """
        Generates and compares response candidates. Recommends the optimal minimum-impact response.
        """
        candidates = []
        
        identity = incident.actors[0] if incident.actors else "unknown"
        assets = incident.affected_assets
        
        # Candidate A: Revoke Identity Session
        # High reversibility, low business impact (if user), high path reduction
        if identity != "unknown":
            is_service_account = "role" in identity.lower() or "service" in identity.lower()
            impact = "high" if is_service_account else "low"
            safety = ResponseSafety.REQUIRES_APPROVAL if is_service_account else ResponseSafety.SAFE_TO_AUTOMATE
            
            candidates.append(ResponseCandidateSchema(
                action="revoke_identity_session",
                target=identity,
                attack_path_reduction=0.90,
                business_impact=impact,
                blast_radius="low",
                reversibility=True,
                confidence=0.85,
                reason="Revoking sessions cuts off the active attacker immediately.",
                approval_required=safety
            ))
            
        # Candidate B: Isolate affected assets
        for asset in assets:
            candidates.append(ResponseCandidateSchema(
                action="isolate_network",
                target=asset,
                attack_path_reduction=0.70,
                business_impact="high",
                blast_radius="medium",
                reversibility=True,
                confidence=0.75,
                reason="Network isolation stops lateral movement but impacts production availability.",
                approval_required=ResponseSafety.REQUIRES_APPROVAL
            ))
            
        # Candidate C: Delete IAM user/role entirely
        if identity != "unknown":
            candidates.append(ResponseCandidateSchema(
                action="delete_identity",
                target=identity,
                attack_path_reduction=1.0,
                business_impact="high",
                blast_radius="high",
                reversibility=False,
                confidence=0.95,
                reason="Irreversible deletion removes all access but causes severe disruption.",
                approval_required=ResponseSafety.BLOCKED
            ))

        if not candidates:
            return {"recommended": None, "alternatives": []}
            
        # Sorting logic: Maximize path reduction, minimize business impact, require reversibility for automation
        def score_candidate(c: ResponseCandidateSchema) -> float:
            score = c.attack_path_reduction * 100
            if c.business_impact == "high":
                score -= 30
            elif c.business_impact == "medium":
                score -= 15
            
            if not c.reversibility:
                score -= 40
                
            return score
            
        candidates.sort(key=score_candidate, reverse=True)
        recommended = candidates[0]
        alternatives = candidates[1:]
        
        return {
            "recommended": recommended.dict(),
            "alternatives": [alt.dict() for alt in alternatives],
            "reason": f"Selected '{recommended.action}' because it offers {recommended.attack_path_reduction*100}% path reduction with {recommended.business_impact} impact.",
            "expected_risk_reduction": recommended.attack_path_reduction,
            "expected_impact": recommended.business_impact,
            "approval_requirement": recommended.approval_required.value
        }
