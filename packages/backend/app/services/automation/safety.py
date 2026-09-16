from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class PolicyResult(str, Enum):
    AUTOMATIC = "AUTOMATIC"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    BLOCKED = "BLOCKED"

class ResponseCandidate(BaseModel):
    action_type: str
    confidence: float
    blast_radius: str  # "LOW", "MEDIUM", "HIGH"
    is_production: bool
    is_reversible: bool
    runbook_mode: str  # "AUTOMATIC" or "APPROVAL_REQUIRED"

class SafetyPolicy:
    """
    Evaluates response candidates to ensure Aegivion never executes
    unsafe, non-allowlisted, or high-blast-radius actions automatically.
    """
    
    # Only these exact actions can be executed by the automation engine
    ALLOWLISTED_ACTIONS = {
        "restrict_security_group_rule",
        "block_s3_public_access",
        "disable_access_key",
        "revoke_session",
        "restrict_nsg_rule",
        "block_azure_storage_public_access",
        "restrict_gcp_firewall_rule",
        "isolate_ec2_instance",
    }

    # Minimum confidence required for ANY automatic action
    MIN_AUTO_CONFIDENCE = 0.90

    def evaluate(self, candidate: ResponseCandidate) -> PolicyResult:
        # 1. Action MUST be allowlisted
        if candidate.action_type not in self.ALLOWLISTED_ACTIONS:
            return PolicyResult.BLOCKED

        # 2. Destructive/Irreversible actions always require approval
        if not candidate.is_reversible:
            return PolicyResult.APPROVAL_REQUIRED

        # 3. High blast radius actions always require approval
        if candidate.blast_radius.upper() == "HIGH":
            return PolicyResult.APPROVAL_REQUIRED

        # 4. Production resources always require approval
        if candidate.is_production:
            return PolicyResult.APPROVAL_REQUIRED

        # 5. Check confidence thresholds
        if candidate.confidence < self.MIN_AUTO_CONFIDENCE:
            return PolicyResult.APPROVAL_REQUIRED

        # 6. If the runbook itself mandates approval
        if candidate.runbook_mode == "APPROVAL_REQUIRED":
            return PolicyResult.APPROVAL_REQUIRED

        # If it passes all safety checks, it can run automatically
        return PolicyResult.AUTOMATIC

safety_policy_engine = SafetyPolicy()
