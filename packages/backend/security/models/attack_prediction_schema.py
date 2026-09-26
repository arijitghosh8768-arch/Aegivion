from pydantic import BaseModel, Field
from typing import List, Dict, Any

class AttackPredictionSchema(BaseModel):
    """
    Signal representing a forecast of the plausible next stage of an active attack.
    This is an intelligence signal, not a certainty.
    """
    current_attack_type: str = Field(..., description="The type of the active attack")
    next_stage: str = Field(..., description="The predicted plausible next stage")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this prediction")
    supporting_evidence: List[str] = Field(default_factory=list, description="Evidence leading to this prediction")
    potential_targets: List[str] = Field(default_factory=list, description="Assets that could be targeted next")
    affected_identity: str = Field(default="unknown", description="The identity executing the attack")
    reason: str = Field(..., description="Explainability for this prediction")
