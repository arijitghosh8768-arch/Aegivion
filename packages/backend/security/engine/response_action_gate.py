from typing import List, Dict, Any, Optional
from security.models.response_candidate_schema import ResponseCandidateSchema, ResponseSafety
from security.models.response_policy_schema import ResponsePolicySchema, GateDecision

class ResponseActionGate:
    """
    The hard safety boundary preventing AI from executing unauthorized cloud actions.
    Candidate != Authorization.
    """
    
    @staticmethod
    def evaluate(
        candidate: ResponseCandidateSchema, 
        policy: ResponsePolicySchema, 
        approval_state: Optional[str] = None
    ) -> GateDecision:
        """
        Receives a candidate response and organizational policy.
        Outputs ALLOW, REQUIRE_APPROVAL, or BLOCK.
        """
        # 1. Action MUST be explicitly allowlisted and enabled
        allowed_match = None
        for allowed in policy.allowlist:
            if allowed.action_type == candidate.action and allowed.enabled:
                allowed_match = allowed
                break
                
        if not allowed_match:
            return GateDecision.BLOCK
            
        # 2. Block universally destructive / irreversible actions regardless of engine proposal
        if not candidate.reversibility and not allowed_match.reversible:
            return GateDecision.BLOCK
            
        # 3. Check organizational/allowlist approval requirement vs candidate safety rating
        if allowed_match.requires_approval or candidate.approval_required == ResponseSafety.REQUIRES_APPROVAL:
            # Action needs approval. Check if it was already granted.
            if approval_state == "APPROVED":
                return GateDecision.ALLOW
            return GateDecision.REQUIRE_APPROVAL
            
        # 4. If all checks pass and it's marked SAFE_TO_AUTOMATE, allow it
        if candidate.approval_required == ResponseSafety.SAFE_TO_AUTOMATE:
            return GateDecision.ALLOW
            
        # Default fail-safe
        return GateDecision.REQUIRE_APPROVAL
