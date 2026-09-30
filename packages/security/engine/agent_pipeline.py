from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class PipelineState(str, Enum):
    RECEIVED = "RECEIVED"
    INGESTED = "INGESTED"
    DETECTED = "DETECTED"
    ANALYZED = "ANALYZED"
    ACTIVATION_EVALUATED = "ACTIVATION_EVALUATED"
    PREDICTED = "PREDICTED"
    RESPONSE_ANALYZED = "RESPONSE_ANALYZED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    RECONCILED = "RECONCILED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DENIED = "DENIED"

class PipelineResult(BaseModel):
    correlation_id: str
    org_id: str
    security_event_id: str
    state: PipelineState
    detections: List[Dict[str, Any]] = Field(default_factory=list)
    activation: Optional[Dict[str, Any]] = None
    prediction: Optional[Dict[str, Any]] = None
    response_recommendation: Optional[Dict[str, Any]] = None
    policy_decision: Optional[Dict[str, Any]] = None
    execution: Optional[Dict[str, Any]] = None
    verification: Optional[Dict[str, Any]] = None
    reconciliation: Optional[Dict[str, Any]] = None
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    provenance: List[str] = Field(default_factory=list)
