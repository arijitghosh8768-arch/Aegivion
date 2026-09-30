import uuid
from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from security.engine.response_safety_policy import PolicyDecision

class ExecutionSource(str, Enum):
    OPTIMIZER = "OPTIMIZER"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    RUNBOOK = "RUNBOOK"
    SYSTEM = "SYSTEM"

class ExecutionAction(str, Enum):
    RESTRICT_IDENTITY_PRIVILEGE = "RESTRICT_IDENTITY_PRIVILEGE"

ALLOWED_ACTIONS = frozenset({ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE})

class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"

class ExecutionState(str, Enum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    ELIGIBILITY_PENDING = "ELIGIBILITY_PENDING"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    READY = "READY"
    EXECUTING = "EXECUTING"
    EXECUTION_SUCCEEDED = "EXECUTION_SUCCEEDED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"

class ExecutionErrorCode(str, Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    POLICY_DENIED = "POLICY_DENIED"
    POLICY_EXPIRED = "POLICY_EXPIRED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_MISSING = "APPROVAL_MISSING"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    INVALID_TARGET = "INVALID_TARGET"
    ADAPTER_UNAVAILABLE = "ADAPTER_UNAVAILABLE"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    EXECUTION_TIMEOUT = "EXECUTION_TIMEOUT"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    ALREADY_EXECUTED = "ALREADY_EXECUTED"
    CANCELLED = "CANCELLED"
    INTERNAL_ERROR = "INTERNAL_ERROR"

class PrivilegeTarget(BaseModel):
    attachment_type: str # "managed" or "inline"
    policy_arn: Optional[str] = None
    policy_name: Optional[str] = None

class PrivilegeExpectedState(BaseModel):
    attached: bool = True

class TargetDescriptor(BaseModel):
    target_type: str
    target_id: str
    provider: Optional[str] = None
    cloud_account_id: Optional[str] = None
    identity_type: Optional[str] = None
    privilege: Optional[PrivilegeTarget] = None
    expected_privilege_state: Optional[PrivilegeExpectedState] = None

class ExecutionRequest(BaseModel):
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str
    requested_by: str
    source: ExecutionSource
    finding_id: str
    action: ExecutionAction
    target: TargetDescriptor
    policy_decision: PolicyDecision
    policy_version: str
    policy_evaluated_at: datetime
    policy_expires_at: Optional[datetime] = None
    approval_required: bool
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    approval_id: Optional[str] = None
    idempotency_key: str
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    dry_run: bool = False

class ExecutionResult(BaseModel):
    execution_id: str
    organization_id: str
    state: ExecutionState
    success: bool
    action: ExecutionAction
    target: TargetDescriptor
    adapter: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_code: Optional[ExecutionErrorCode] = None
    error_message: Optional[str] = None
    provider_request_id: Optional[str] = None
    provider_response_metadata: Dict[str, Any] = Field(default_factory=dict)
    idempotent_replay: bool = False
    correlation_id: str

class ExecutionEligibilityResult(BaseModel):
    eligible: bool
    reason: str
    error_code: Optional[ExecutionErrorCode] = None
    checks: Dict[str, bool] = Field(default_factory=dict)
    
class CloudResponseAdapter:
    def supports(self, action: ExecutionAction, target: TargetDescriptor) -> bool:
        raise NotImplementedError()
        
    def validate_target(self, target: TargetDescriptor) -> bool:
        raise NotImplementedError()
        
    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        raise NotImplementedError()
        
    def provider_name(self) -> str:
        raise NotImplementedError()

class MockIdentityPrivilegeAdapter(CloudResponseAdapter):
    def supports(self, action: ExecutionAction, target: TargetDescriptor) -> bool:
        return action == ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE and target.target_type == "identity"
        
    def validate_target(self, target: TargetDescriptor) -> bool:
        if target.target_type != "identity" or not target.target_id:
            return False
            
        if target.privilege:
            if target.privilege.attachment_type not in ["managed", "inline"]:
                return False
            if target.privilege.attachment_type == "managed":
                if not target.privilege.policy_arn or target.privilege.policy_name:
                    return False
            if target.privilege.attachment_type == "inline":
                if not target.privilege.policy_name or target.privilege.policy_arn:
                    return False
        return True
        
    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        return ExecutionResult(
            execution_id=request.execution_id,
            organization_id=request.organization_id,
            state=ExecutionState.EXECUTION_SUCCEEDED,
            success=True,
            action=request.action,
            target=request.target,
            adapter=self.provider_name(),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            provider_request_id=f"sim-{uuid.uuid4()}",
            provider_response_metadata={
                "provider": "mock",
                "simulated": True,
                "operation": request.action.value
            },
            idempotent_replay=False,
            correlation_id=request.correlation_id
        )
        
    def provider_name(self) -> str:
        return "MockAdapter"
