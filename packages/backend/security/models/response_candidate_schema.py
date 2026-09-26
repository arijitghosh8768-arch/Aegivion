from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum

class ResponseSafety(str, Enum):
    SAFE_TO_AUTOMATE = "SAFE_TO_AUTOMATE"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    BLOCKED = "BLOCKED"

class ResponseCandidateSchema(BaseModel):
    """
    Candidate action to mitigate an active attack path.
    """
    action: str = Field(..., description="The remediation action (e.g., 'revoke_session', 'isolate_instance')")
    target: str = Field(..., description="The target asset or identity")
    attack_path_reduction: float = Field(..., ge=0.0, le=1.0, description="Estimated percentage of path risk reduced")
    business_impact: str = Field(..., description="Estimated impact: low, medium, high")
    blast_radius: str = Field(..., description="Estimated blast radius of the response itself")
    reversibility: bool = Field(..., description="Can this action be easily reverted?")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence that this action works without breaking intended functionality")
    reason: str = Field(..., description="Why this candidate was generated")
    approval_required: ResponseSafety = Field(..., description="Safety classification of this action")
