from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

class ApprovalState(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"

class ApprovalRequest(BaseModel):
    approval_id: str
    org_id: str
    finding_id: str
    execution_request_id: str
    target_id: str
    action: str
    requested_by: str
    requested_at: str
    expires_at: str
    status: ApprovalState = ApprovalState.PENDING
    
    # Context snapshots
    policy_version: str
    risk_score: float
    activation_state: str
    prediction: Dict[str, Any]
    optimizer_decision: Dict[str, Any]
    safety_decision: Dict[str, Any]
    simulation_summary: str
    evidence_summary: str
    business_impact: str
    blast_radius: str
    reversibility: str
    approval_reason: str
    
    # Audit info
    decision_by: Optional[str] = None
    decision_at: Optional[str] = None
    decision_reason: Optional[str] = None
    
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
class ApprovalAuditRecord(BaseModel):
    audit_id: str
    approval_id: str
    org_id: str
    execution_request_id: str
    requested_by: str
    requested_at: str
    decision: str
    decision_by: str
    decision_at: str
    decision_reason: str
    policy_version: str
    risk_score: float
    activation_state: str
    action: str
    target: str
    expiry: str
    fresh_validation_result: Dict[str, Any]
    execution_started_at: Optional[str] = None
    execution_result: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
