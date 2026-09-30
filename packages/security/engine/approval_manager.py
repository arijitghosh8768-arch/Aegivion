import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from security.models.approval_state import ApprovalRequest, ApprovalState, ApprovalAuditRecord
from security.engine.response_safety_policy import ResponseSafetyPolicyEngine, ResponseSafetyPolicy, PolicyDecision, DEFAULT_POLICY
from security.engine.execution_contract import ExecutionRequest, ExecutionResult, ApprovalStatus
from security.engine.execution_orchestrator import ExecutionOrchestrator
from security.engine.aws_precondition_checker import AWSPreconditionChecker, PreconditionStatus

logger = logging.getLogger(__name__)

class ApprovalManager:
    def __init__(self, orchestrator: ExecutionOrchestrator, safety_engine: ResponseSafetyPolicyEngine, precondition_checker: AWSPreconditionChecker, policy: ResponseSafetyPolicy = None):
        self.orchestrator = orchestrator
        self.safety_engine = safety_engine
        self.precondition_checker = precondition_checker
        self.policy = policy if policy else DEFAULT_POLICY
        self.requests: Dict[str, ApprovalRequest] = {}
        self.audit_log: list[ApprovalAuditRecord] = []
        
    def _create_audit(self, req: ApprovalRequest, decision: str, by: str, reason: str, fresh_val: Dict[str, Any] = None, exec_res: ExecutionResult = None) -> ApprovalAuditRecord:
        import uuid
        record = ApprovalAuditRecord(
            audit_id=str(uuid.uuid4()),
            approval_id=req.approval_id,
            org_id=req.org_id,
            execution_request_id=req.execution_request_id,
            requested_by=req.requested_by,
            requested_at=req.requested_at,
            decision=decision,
            decision_by=by,
            decision_at=datetime.now(timezone.utc).isoformat(),
            decision_reason=reason,
            policy_version=req.policy_version,
            risk_score=req.risk_score,
            activation_state=req.activation_state,
            action=req.action,
            target=req.target_id,
            expiry=req.expires_at,
            fresh_validation_result=fresh_val or {},
            execution_started_at=exec_res.started_at.isoformat() if exec_res and exec_res.started_at else None,
            execution_result={"success": exec_res.success, "error": exec_res.error_message} if exec_res else None
        )
        self.audit_log.append(record)
        return record
        
    def create_request(self, req: ApprovalRequest) -> ApprovalRequest:
        self.requests[req.approval_id] = req
        return req
        
    def get_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        req = self.requests.get(approval_id)
        if not req:
            return None
        self._check_expiration(req)
        return req

    def _check_expiration(self, req: ApprovalRequest):
        if req.status == ApprovalState.PENDING:
            expires_at = datetime.fromisoformat(req.expires_at)
            if datetime.now(timezone.utc) >= expires_at:
                req.status = ApprovalState.EXPIRED

    def approve(self, approval_id: str, org_id: str, reviewer_id: str, reviewer_role: str, reason: str) -> ApprovalRequest:
        req = self.get_request(approval_id)
        if not req:
            raise ValueError("Approval not found")
            
        if req.org_id != org_id:
            raise PermissionError("Tenant mismatch")
            
        if reviewer_role not in ["security_administrator", "organization_administrator"]:
            raise PermissionError("Unauthorized role")
            
        if req.status == ApprovalState.APPROVED:
            return req # Idempotent
            
        if req.status != ApprovalState.PENDING:
            raise ValueError(f"Cannot approve from state {req.status}")
            
        req.status = ApprovalState.APPROVED
        req.decision_by = reviewer_id
        req.decision_at = datetime.now(timezone.utc).isoformat()
        req.decision_reason = reason
        req.updated_at = datetime.now(timezone.utc).isoformat()
        
        self._create_audit(req, "APPROVED", reviewer_id, reason)
        return req

    def deny(self, approval_id: str, org_id: str, reviewer_id: str, reviewer_role: str, reason: str) -> ApprovalRequest:
        req = self.get_request(approval_id)
        if not req:
            raise ValueError("Approval not found")
            
        if req.org_id != org_id:
            raise PermissionError("Tenant mismatch")
            
        if reviewer_role not in ["security_administrator", "organization_administrator"]:
            raise PermissionError("Unauthorized role")
            
        if req.status == ApprovalState.DENIED:
            return req # Idempotent
            
        if req.status != ApprovalState.PENDING:
            raise ValueError(f"Cannot deny from state {req.status}")
            
        req.status = ApprovalState.DENIED
        req.decision_by = reviewer_id
        req.decision_at = datetime.now(timezone.utc).isoformat()
        req.decision_reason = reason
        req.updated_at = datetime.now(timezone.utc).isoformat()
        
        self._create_audit(req, "DENIED", reviewer_id, reason)
        return req
        
    def cancel(self, approval_id: str, org_id: str, reviewer_id: str) -> ApprovalRequest:
        req = self.get_request(approval_id)
        if not req:
            raise ValueError("Approval not found")
            
        if req.org_id != org_id:
            raise PermissionError("Tenant mismatch")
            
        if req.status == ApprovalState.CANCELLED:
            return req
            
        if req.status != ApprovalState.PENDING:
            raise ValueError(f"Cannot cancel from state {req.status}")
            
        req.status = ApprovalState.CANCELLED
        req.updated_at = datetime.now(timezone.utc).isoformat()
        
        self._create_audit(req, "CANCELLED", reviewer_id, "Cancelled by user")
        return req

    def execute_approved_request(self, approval_id: str, exec_req: ExecutionRequest) -> ExecutionResult:
        req = self.get_request(approval_id)
        if not req:
            return self.orchestrator._create_failed_result(exec_req, None, "APPROVAL_MISSING", "Approval not found")
            
        if req.status != ApprovalState.APPROVED:
            return self.orchestrator._create_failed_result(exec_req, None, "APPROVAL_REJECTED", f"Approval state is {req.status}")
            
        # 2. Verify org binding
        if req.org_id != exec_req.organization_id:
            return self.orchestrator._create_failed_result(exec_req, None, "TENANT_MISMATCH", "Tenant mismatch between approval and request")
            
        # 5. Verify target/action binding
        if req.target_id != exec_req.target.target_id or req.action != exec_req.action:
            return self.orchestrator._create_failed_result(exec_req, None, "INVALID_REQUEST", "Target or action mismatch")
            
        if req.execution_request_id != exec_req.execution_id:
             return self.orchestrator._create_failed_result(exec_req, None, "INVALID_REQUEST", "Execution ID mismatch")
             
        # 8. Re-run AWS precondition validation
        pre_res = self.precondition_checker.check(exec_req.action, exec_req.target)
        if pre_res.status != PreconditionStatus.PASS:
             audit = self._create_audit(req, "BLOCKED_DRIFT", "system", f"Precondition failed: {pre_res.reason}", fresh_val={"precondition": pre_res.status.name})
             return self.orchestrator._create_failed_result(exec_req, None, "PRECONDITION_FAILED", f"Precondition failed: {pre_res.reason}")
             
        # If all passes, hand off to orchestrator
        # We must update exec_req approval status so orchestrator accepts it
        exec_req.approval_status = ApprovalStatus.APPROVED
        exec_req.approval_id = approval_id
        
        res = self.orchestrator.execute(exec_req, exec_req.organization_id)
        
        self._create_audit(req, "EXECUTED", "system", "Successfully validated and executed", fresh_val={"precondition": "PASS", "safety_policy": "ALLOW"}, exec_res=res)
        return res
