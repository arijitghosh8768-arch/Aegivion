from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class AttackActivationSchema(BaseModel):
    """
    Contract representing the dynamic activation of an attack based on real-time events.
    This is separate from static path risk.
    """
    activation_score: float = Field(..., ge=0.0, le=100.0, description="0-100 score of active attack probability")
    
    # Evidence breakdown
    signals: Dict[str, Any] = Field(default_factory=dict, description="Detailed score contributions")
    
    # Context
    attack_types: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    affected_identities: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
