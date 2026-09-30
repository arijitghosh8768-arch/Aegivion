import pytest
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
import uuid

from security.models.approval_state import ApprovalRequest, ApprovalState
from security.engine.approval_manager import ApprovalManager
from security.engine.execution_contract import ExecutionRequest, TargetDescriptor, ExecutionState
from security.engine.execution_orchestrator import ExecutionOrchestrator
from security.engine.response_safety_policy import ResponseSafetyPolicyEngine
from security.engine.aws_precondition_checker import AWSPreconditionChecker, PreconditionStatus

class MockSession:
    def client(self, *args, **kwargs):
        pass

class MockPreconditionChecker(AWSPreconditionChecker):
    def __init__(self, status=PreconditionStatus.PASS):
        self._status = status
    def check(self, action, target):
        from security.engine.aws_precondition_checker import PreconditionResult
        return PreconditionResult(status=self._status, reason="Mock reason", checked_at=datetime.now(timezone.utc))

class MockOrchestrator(ExecutionOrchestrator):
    def __init__(self):
        super().__init__()
        
    def _create_failed_result(self, request, state, error_code, reason, adapter_name="None"):
        from security.engine.execution_contract import ExecutionResult
        return ExecutionResult(
            execution_id=request.execution_id,
            organization_id=request.organization_id,
            state=state or ExecutionState.REJECTED,
            success=False,
            action=request.action,
            target=request.target,
            adapter=adapter_name,
            error_code=error_code,
            error_message=reason,
            correlation_id=request.correlation_id
        )

@pytest.fixture
def orchestrator():
    return MockOrchestrator()
    
@pytest.fixture
def safety_engine():
    return ResponseSafetyPolicyEngine()

@pytest.fixture
def precondition_checker():
    return MockPreconditionChecker()
    
@pytest.fixture
def manager(orchestrator, safety_engine, precondition_checker):
    return ApprovalManager(orchestrator, safety_engine, precondition_checker)

def _create_request(org_id="org1") -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=str(uuid.uuid4()),
        org_id=org_id,
        finding_id="f1",
        execution_request_id="exec1",
        target_id="arn:aws:iam::123:role/foo",
        action="RESTRICT_IDENTITY_PRIVILEGE",
        requested_by="sys",
        requested_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
        policy_version="1.0",
        risk_score=0.9,
        activation_state="ACTIVE",
        prediction={},
        optimizer_decision={},
        safety_decision={},
        simulation_summary="sim",
        evidence_summary="ev",
        business_impact="low",
        blast_radius="low",
        reversibility="high",
        approval_reason="Needs human"
    )

def test_create_approval_request(manager):
    req = _create_request()
    manager.create_request(req)
    assert manager.get_request(req.approval_id) is not None
    assert manager.get_request(req.approval_id).status == ApprovalState.PENDING

def test_tenant_isolation(manager):
    req = _create_request(org_id="org1")
    manager.create_request(req)
    with pytest.raises(PermissionError, match="Tenant mismatch"):
        manager.approve(req.approval_id, "org2", "u1", "security_administrator", "ok")

def test_unauthorized_reviewer_rejected(manager):
    req = _create_request()
    manager.create_request(req)
    with pytest.raises(PermissionError, match="Unauthorized role"):
        manager.approve(req.approval_id, "org1", "u1", "member", "ok")

def test_authorized_reviewer_accepted(manager):
    req = _create_request()
    manager.create_request(req)
    res = manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")
    assert res.status == ApprovalState.APPROVED

def test_pending_to_denied(manager):
    req = _create_request()
    manager.create_request(req)
    res = manager.deny(req.approval_id, "org1", "u1", "security_administrator", "no")
    assert res.status == ApprovalState.DENIED

def test_pending_to_expired(manager):
    req = _create_request()
    req.expires_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    manager.create_request(req)
    assert manager.get_request(req.approval_id).status == ApprovalState.EXPIRED
    
    with pytest.raises(ValueError, match="Cannot approve"):
        manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")

def test_invalid_transition_rejected(manager):
    req = _create_request()
    manager.create_request(req)
    manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")
    with pytest.raises(ValueError, match="Cannot deny from state ApprovalState.APPROVED"):
        manager.deny(req.approval_id, "org1", "u2", "security_administrator", "no")

def test_duplicate_approval_idempotency(manager):
    req = _create_request()
    manager.create_request(req)
    manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")
    res = manager.approve(req.approval_id, "org1", "u2", "security_administrator", "ok again")
    assert res.decision_by == "u1" # First decision sticks

def test_duplicate_denial_idempotency(manager):
    req = _create_request()
    manager.create_request(req)
    manager.deny(req.approval_id, "org1", "u1", "security_administrator", "no")
    res = manager.deny(req.approval_id, "org1", "u2", "security_administrator", "no again")
    assert res.decision_by == "u1"

def _create_exec_req(action, target_id) -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="exec1",
        organization_id="org1",
        correlation_id="c1",
        source="SYSTEM",
        requested_by="sys",
        finding_id="f1",
        policy_version="1.0",
        policy_evaluated_at=datetime.now(timezone.utc),
        approval_required=True,
        idempotency_key="key1",
        action=action,
        target=TargetDescriptor(target_type="identity", target_id=target_id, provider="aws"),
        policy_decision="ALLOW"
    )

def test_approval_bound_to_execution_request(manager):
    req = _create_request()
    manager.create_request(req)
    manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")
    
    exec_req = _create_exec_req("RESTRICT_IDENTITY_PRIVILEGE", "arn:aws:iam::123:role/foo")
    exec_req.execution_id = "wrong_exec"
    res = manager.execute_approved_request(req.approval_id, exec_req)
    assert res.success is False
    assert res.error_code == "INVALID_REQUEST"

def test_wrong_target_rejected(manager):
    req = _create_request()
    manager.create_request(req)
    manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")
    
    exec_req = _create_exec_req("RESTRICT_IDENTITY_PRIVILEGE", "arn:aws:iam::123:role/bar")
    res = manager.execute_approved_request(req.approval_id, exec_req)
    assert res.success is False
    assert res.error_code == "INVALID_REQUEST"

def test_wrong_action_rejected(manager):
    req = _create_request()
    # We will just change req.action so that it mismatches exec_req.action
    req.action = "SOME_OTHER_ACTION"
    manager.create_request(req)
    manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")
    
    exec_req = _create_exec_req("RESTRICT_IDENTITY_PRIVILEGE", "arn:aws:iam::123:role/foo")
    res = manager.execute_approved_request(req.approval_id, exec_req)
    assert res.success is False
    assert res.error_code == "INVALID_REQUEST"

def test_aws_precondition_drift(orchestrator, safety_engine):
    pre_checker = MockPreconditionChecker(PreconditionStatus.FAIL_DRIFT)
    manager = ApprovalManager(orchestrator, safety_engine, pre_checker)
    
    req = _create_request()
    manager.create_request(req)
    manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")
    
    exec_req = _create_exec_req("RESTRICT_IDENTITY_PRIVILEGE", "arn:aws:iam::123:role/foo")
    res = manager.execute_approved_request(req.approval_id, exec_req)
    assert res.success is False
    assert res.error_code == "PRECONDITION_FAILED"

def test_approved_request_reaches_orchestrator(manager):
    req = _create_request()
    manager.create_request(req)
    manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")
    
    exec_req = _create_exec_req("RESTRICT_IDENTITY_PRIVILEGE", "arn:aws:iam::123:role/foo")
    res = manager.execute_approved_request(req.approval_id, exec_req)
    assert res.success is False
    assert res.error_code == "ADAPTER_UNAVAILABLE"

def test_denied_request_never_reaches_execution(manager):
    req = _create_request()
    manager.create_request(req)
    manager.deny(req.approval_id, "org1", "u1", "security_administrator", "no")
    
    exec_req = _create_exec_req("RESTRICT_IDENTITY_PRIVILEGE", "arn:aws:iam::123:role/foo")
    res = manager.execute_approved_request(req.approval_id, exec_req)
    assert res.success is False
    assert res.error_code == "APPROVAL_REJECTED"

def test_audit_record_created(manager):
    req = _create_request()
    manager.create_request(req)
    manager.approve(req.approval_id, "org1", "u1", "security_administrator", "ok")
    
    assert len(manager.audit_log) == 1
    assert manager.audit_log[0].decision == "APPROVED"
    assert manager.audit_log[0].decision_reason == "ok"
    assert manager.audit_log[0].decision_by == "u1"
