from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum

class GateDecision(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"

class AllowedActionSchema(BaseModel):
    action_type: str
    target_type: str = Field(default="*")
    provider: str = Field(default="*")
    requires_approval: bool = Field(default=True)
    reversible: bool = Field(default=True)
    enabled: bool = Field(default=True)

class ResponsePolicySchema(BaseModel):
    """
    Contract for the organizational safety policy.
    Dictates what actions the system is allowed to take.
    """
    allowlist: List[AllowedActionSchema] = Field(default_factory=list)
    auto_approve_non_prod: bool = Field(default=False)
