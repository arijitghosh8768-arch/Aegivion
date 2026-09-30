import os
import logging
from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from security.engine.execution_contract import ExecutionRequest, ExecutionEligibilityResult, ExecutionErrorCode, ApprovalStatus
from security.engine.response_safety_policy import PolicyDecision

logger = logging.getLogger(__name__)

class SafetyDecision(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EMERGENCY_STOP = "EMERGENCY_STOP"
    RATE_LIMITED = "RATE_LIMITED"
    BLAST_RADIUS_EXCEEDED = "BLAST_RADIUS_EXCEEDED"

class SafetyPolicyResult:
    def __init__(self, decision: SafetyDecision, reason: str, error_code: Optional[ExecutionErrorCode] = None):
        self.decision = decision
        self.reason = reason
        self.error_code = error_code

class SafetyController:
    """
    Phase 7A: Central Safety Controller / Interceptor.
    The absolute final security boundary before cloud execution.
    """
    def __init__(self):
        # Global kill switch (Emergency Stop)
        # Defaulting to ENABLED for normal operation, can be set via env var
        self.autonomous_response_enabled = os.environ.get("AUTONOMOUS_RESPONSE", "ENABLED").upper() == "ENABLED"
        
        self.protected_targets = [
            "arn:aws:iam::123456789012:role/organizationaccountaccessrole", 
            "admin", 
            "root"
        ]

    def evaluate(self, request: ExecutionRequest, tenant_context: str) -> SafetyPolicyResult:
        # 1. EMERGENCY STOP (Kill Switch)
        if not self.autonomous_response_enabled:
            return SafetyPolicyResult(
                decision=SafetyDecision.EMERGENCY_STOP,
                reason="Global autonomous response is DISABLED (Emergency Stop active).",
                error_code=ExecutionErrorCode.ACTION_NOT_ALLOWED
            )
            
        # 2. Tenant RBAC Isolation
        if request.organization_id != tenant_context:
            return SafetyPolicyResult(
                decision=SafetyDecision.DENY,
                reason="Tenant mismatch (RBAC violation).",
                error_code=ExecutionErrorCode.TENANT_MISMATCH
            )
            
        # 3. Target Protection (Critical Assets)
        target_id = request.target.target_id.lower() if request.target and request.target.target_id else ""
        if any(protected in target_id for protected in self.protected_targets):
            return SafetyPolicyResult(
                decision=SafetyDecision.DENY,
                reason=f"Target '{request.target.target_id}' matches a protected critical asset.",
                error_code=ExecutionErrorCode.INVALID_TARGET
            )

        # 4. Policy Version & Validity
        if request.policy_decision not in [PolicyDecision.ALLOW, PolicyDecision.REQUIRE_APPROVAL]:
            return SafetyPolicyResult(
                decision=SafetyDecision.DENY,
                reason=f"Invalid policy decision: {request.policy_decision}",
                error_code=ExecutionErrorCode.POLICY_DENIED
            )
            
        if request.policy_expires_at and datetime.now(timezone.utc) > request.policy_expires_at:
            return SafetyPolicyResult(
                decision=SafetyDecision.DENY,
                reason="Safety policy has expired.",
                error_code=ExecutionErrorCode.POLICY_EXPIRED
            )

        # 5. Approval Validity
        if request.policy_decision == PolicyDecision.REQUIRE_APPROVAL or request.approval_required:
            if request.approval_status == ApprovalStatus.REJECTED:
                return SafetyPolicyResult(
                    decision=SafetyDecision.DENY,
                    reason="Human approval was rejected.",
                    error_code=ExecutionErrorCode.APPROVAL_REJECTED
                )
            elif request.approval_status == ApprovalStatus.EXPIRED:
                return SafetyPolicyResult(
                    decision=SafetyDecision.DENY,
                    reason="Human approval expired.",
                    error_code=ExecutionErrorCode.APPROVAL_EXPIRED
                )
            elif request.approval_status != ApprovalStatus.APPROVED or not request.approval_id:
                return SafetyPolicyResult(
                    decision=SafetyDecision.REQUIRE_APPROVAL,
                    reason="Human approval is pending or missing.",
                    error_code=ExecutionErrorCode.APPROVAL_MISSING
                )

        # 6. Blast Radius (Phase 7C placeholder - for now, always ALLOW if we get here)
        # 7. Rate Limits (Phase 7C placeholder)

        # If all checks pass
        return SafetyPolicyResult(
            decision=SafetyDecision.ALLOW,
            reason="All safety checks passed."
        )
