from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

class SecurityReplaySchema(BaseModel):
    """
    Immutable, read-only decision trace of the full autonomous lifecycle.
    """
    trace_id: str = Field(..., description="Unique identifier for the decision trace")
    incident_id: str = Field(..., description="Associated Incident ID")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Context
    events: List[Dict[str, Any]] = Field(default_factory=list)
    detector_results: Dict[str, Any] = Field(default_factory=dict)
    
    # Analysis
    correlation_storyline: Dict[str, Any] = Field(default_factory=dict)
    attack_activation: Dict[str, Any] = Field(default_factory=dict)
    dynamic_path_risk: Dict[str, Any] = Field(default_factory=dict)
    predictions: List[Dict[str, Any]] = Field(default_factory=list)
    what_if_simulation: Dict[str, Any] = Field(default_factory=dict)
    
    # Response
    response_candidates: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_action: Optional[Dict[str, Any]] = Field(default=None)
    safety_decision: str = Field(..., description="ALLOW, REQUIRE_APPROVAL, or BLOCK")
    approval_state: Optional[str] = Field(default=None)
    
    # Execution & Verification
    execution_result: Optional[Dict[str, Any]] = Field(default=None)
    before_state: Optional[Dict[str, Any]] = Field(default=None)
    after_state: Optional[Dict[str, Any]] = Field(default=None)
    verification_result: Optional[str] = Field(default=None, description="threat reduced, threat unchanged, etc.")
