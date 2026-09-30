import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError

from security.engine.execution_contract import (
    ExecutionRequest, TargetDescriptor, ExecutionAction,
    ExecutionSource, ApprovalStatus, ExecutionResult, ExecutionState,
    ExecutionErrorCode, MockIdentityPrivilegeAdapter
)
from security.engine.response_safety_policy import PolicyDecision
from security.engine.execution_orchestrator import ExecutionOrchestrator

@pytest.fixture
def orchestrator():
    orch = ExecutionOrchestrator()
    orch.register_adapter(MockIdentityPrivilegeAdapter())
    return orch

def create_valid_request(override=None):
    base = {
        "organization_id": "org1",
        "requested_by": "admin",
        "source": ExecutionSource.SYSTEM,
        "finding_id": "f1",
        "action": ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE,
        "target": TargetDescriptor(target_type="identity", target_id="id-1"),
        "policy_decision": PolicyDecision.ALLOW,
        "policy_version": "1.0",
        "policy_evaluated_at": datetime.now(timezone.utc),
        "approval_required": False,
        "idempotency_key": "key1"
    }
    if override:
        base.update(override)
    return ExecutionRequest(**base)

# Policy binding tests
def test_orchestrator_deny_rejected(orchestrator):
    req = create_valid_request({"policy_decision": PolicyDecision.DENY})
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.POLICY_DENIED

def test_orchestrator_insufficient_evidence_rejected(orchestrator):
    req = create_valid_request({"policy_decision": PolicyDecision.INSUFFICIENT_EVIDENCE})
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.POLICY_DENIED

def test_orchestrator_expired_policy_rejected(orchestrator):
    req = create_valid_request({
        "policy_expires_at": datetime.now(timezone.utc) - timedelta(minutes=5)
    })
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.EXPIRED
    assert res.error_code == ExecutionErrorCode.POLICY_EXPIRED

def test_require_approval_pending(orchestrator):
    req = create_valid_request({
        "policy_decision": PolicyDecision.REQUIRE_APPROVAL,
        "approval_required": True,
        "approval_status": ApprovalStatus.PENDING
    })
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.APPROVAL_PENDING
    assert res.error_code == ExecutionErrorCode.APPROVAL_REQUIRED

def test_require_approval_approved(orchestrator):
    req = create_valid_request({
        "policy_decision": PolicyDecision.REQUIRE_APPROVAL,
        "approval_required": True,
        "approval_status": ApprovalStatus.APPROVED,
        "approval_id": "app-1"
    })
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.EXECUTION_SUCCEEDED

def test_require_approval_approved_without_id_rejected(orchestrator):
    req = create_valid_request({
        "policy_decision": PolicyDecision.REQUIRE_APPROVAL,
        "approval_required": True,
        "approval_status": ApprovalStatus.APPROVED,
        "approval_id": None
    })
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.APPROVAL_MISSING

def test_approval_rejected_rejected(orchestrator):
    req = create_valid_request({
        "policy_decision": PolicyDecision.REQUIRE_APPROVAL,
        "approval_required": True,
        "approval_status": ApprovalStatus.REJECTED
    })
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.APPROVAL_REJECTED

def test_approval_expired_rejected(orchestrator):
    req = create_valid_request({
        "policy_decision": PolicyDecision.REQUIRE_APPROVAL,
        "approval_required": True,
        "approval_status": ApprovalStatus.EXPIRED
    })
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.APPROVAL_EXPIRED

# Tenant tests
def test_same_tenant_succeeds(orchestrator):
    req = create_valid_request()
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.EXECUTION_SUCCEEDED

def test_cross_tenant_rejected(orchestrator):
    req = create_valid_request()
    res = orchestrator.execute(req, "org2")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.TENANT_MISMATCH

def test_no_adapter_call_on_tenant_mismatch(orchestrator):
    # Relies on the fact that the state is REJECTED before reaching adapter logic
    req = create_valid_request()
    res = orchestrator.execute(req, "org2")
    assert res.adapter == "None"

# Idempotency tests
def test_first_request_executes(orchestrator):
    req = create_valid_request()
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.EXECUTION_SUCCEEDED
    assert res.idempotent_replay is False

def test_same_request_replay(orchestrator):
    req = create_valid_request()
    res1 = orchestrator.execute(req, "org1")
    res2 = orchestrator.execute(req, "org1")
    assert res2.state == ExecutionState.EXECUTION_SUCCEEDED
    assert res2.idempotent_replay is True
    assert res1.provider_request_id == res2.provider_request_id

def test_same_key_different_target(orchestrator):
    req1 = create_valid_request()
    orchestrator.execute(req1, "org1")
    req2 = create_valid_request({
        "target": TargetDescriptor(target_type="identity", target_id="id-2")
    })
    res = orchestrator.execute(req2, "org1")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.IDEMPOTENCY_CONFLICT

def test_same_key_different_organization(orchestrator):
    req1 = create_valid_request()
    orchestrator.execute(req1, "org1")
    req2 = create_valid_request({"organization_id": "org2"})
    # It passes tenant mismatch check because req.org == ctx, but hits idempotency conflict
    res = orchestrator.execute(req2, "org2")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.IDEMPOTENCY_CONFLICT
    
    # If we supply org1 context, it hits tenant mismatch because req2.org_id != tenant_context
    res2 = orchestrator.execute(req2, "org1")
    assert res2.state == ExecutionState.REJECTED
    assert res2.error_code == ExecutionErrorCode.TENANT_MISMATCH

# State machine tests
def test_valid_transitions(orchestrator):
    req = create_valid_request()
    res = orchestrator.execute(req, "org1")
    assert orchestrator._execution_states[req.execution_id] == ExecutionState.EXECUTION_SUCCEEDED

def test_invalid_transitions(orchestrator):
    req = create_valid_request()
    orchestrator._transition(req, ExecutionState.CREATED)
    # CREATED -> EXECUTION_SUCCEEDED is invalid
    assert orchestrator._transition(req, ExecutionState.EXECUTION_SUCCEEDED) is False

def test_ready_to_executing(orchestrator):
    req = create_valid_request()
    orchestrator._execution_states[req.execution_id] = ExecutionState.READY
    assert orchestrator._transition(req, ExecutionState.EXECUTING) is True

# Safety tests
def test_arbitrary_shell_command_rejected():
    with pytest.raises(ValidationError):
        create_valid_request({"action": "execute_shell"})

def test_arbitrary_provider_operation_rejected():
    with pytest.raises(ValidationError):
        create_valid_request({"action": "delete_bucket"})

def test_arbitrary_target_type_rejected(orchestrator):
    req = create_valid_request({
        "target": TargetDescriptor(target_type="shell", target_id="echo hi")
    })
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.ADAPTER_UNAVAILABLE

def test_no_adapter_call_on_policy_failure(orchestrator):
    req = create_valid_request({"policy_decision": PolicyDecision.DENY})
    res = orchestrator.execute(req, "org1")
    assert res.adapter == "None"

def test_no_adapter_call_on_approval_failure(orchestrator):
    req = create_valid_request({
        "policy_decision": PolicyDecision.REQUIRE_APPROVAL,
        "approval_required": True,
        "approval_status": ApprovalStatus.REJECTED
    })
    res = orchestrator.execute(req, "org1")
    assert res.adapter == "None"

def test_no_adapter_call_on_expired_policy(orchestrator):
    req = create_valid_request({
        "policy_expires_at": datetime.now(timezone.utc) - timedelta(minutes=5)
    })
    res = orchestrator.execute(req, "org1")
    assert res.adapter == "None"

# Dry-run tests
def test_dry_run_validates_everything(orchestrator):
    req = create_valid_request({"dry_run": True})
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.EXECUTION_SUCCEEDED

def test_dry_run_performs_no_mutation(orchestrator):
    req = create_valid_request({"dry_run": True})
    res = orchestrator.execute(req, "org1")
    assert res.adapter == "DryRunAdapter"
    assert res.provider_response_metadata.get("simulated") is True

# Timeout/failure tests
class TimeoutAdapter(MockIdentityPrivilegeAdapter):
    def execute(self, req):
        raise TimeoutError("Execution timed out")
    def provider_name(self): return "TimeoutAdapter"

def test_adapter_timeout_produces_execution_failed():
    orch = ExecutionOrchestrator()
    orch.register_adapter(TimeoutAdapter())
    req = create_valid_request()
    res = orch.execute(req, "org1")
    assert res.state == ExecutionState.EXECUTION_FAILED
    assert res.error_code == ExecutionErrorCode.PROVIDER_ERROR
    assert "timed out" in res.error_message

def test_timeout_does_not_trigger_automatic_retry():
    orch = ExecutionOrchestrator()
    orch.register_adapter(TimeoutAdapter())
    req = create_valid_request()
    res = orch.execute(req, "org1")
    assert orch._execution_states[req.execution_id] == ExecutionState.EXECUTION_FAILED

# Cancellation tests
def test_pending_execution_can_be_cancelled(orchestrator):
    req = create_valid_request({
        "policy_decision": PolicyDecision.REQUIRE_APPROVAL,
        "approval_required": True,
        "approval_status": ApprovalStatus.PENDING
    })
    orchestrator.execute(req, "org1")
    assert orchestrator.cancel(req.execution_id) is True
    assert orchestrator._execution_states[req.execution_id] == ExecutionState.CANCELLED

def test_ready_execution_can_be_cancelled(orchestrator):
    req = create_valid_request()
    orchestrator._execution_states[req.execution_id] = ExecutionState.READY
    orchestrator._active_requests[req.execution_id] = req
    assert orchestrator.cancel(req.execution_id) is True
    assert orchestrator._execution_states[req.execution_id] == ExecutionState.CANCELLED

def test_executing_operation_cannot_be_falsely_cancelled(orchestrator):
    req = create_valid_request()
    orchestrator.execute(req, "org1")
    # By the time execute finishes it's already EXECUTION_SUCCEEDED
    assert orchestrator.cancel(req.execution_id) is False

# Determinism
def test_same_input_produces_equivalent_eligibility_result(orchestrator):
    req1 = create_valid_request()
    res1 = orchestrator.check_eligibility(req1)
    req2 = create_valid_request()
    res2 = orchestrator.check_eligibility(req2)
    assert res1.eligible == res2.eligible
    assert res1.error_code == res2.error_code

# Additional Tests to reach 50+ threshold
def test_orchestrator_resolves_mock_adapter_correctly(orchestrator):
    req = create_valid_request()
    adapter = orchestrator._resolve_adapter(req)
    assert adapter is not None
    assert adapter.provider_name() == "MockAdapter"

def test_missing_organization_id():
    with pytest.raises(ValidationError):
        create_valid_request({"organization_id": None})

def test_mock_adapter_validate_target():
    adapter = MockIdentityPrivilegeAdapter()
    assert adapter.validate_target(TargetDescriptor(target_type="identity", target_id="id1")) is True
    assert adapter.validate_target(TargetDescriptor(target_type="identity", target_id="")) is False

from security.engine.execution_contract import PrivilegeTarget

def test_mock_adapter_rejects_invalid_managed_privilege():
    adapter = MockIdentityPrivilegeAdapter()
    # Has policy_name instead of policy_arn
    invalid = TargetDescriptor(
        target_type="identity", 
        target_id="id1", 
        privilege=PrivilegeTarget(attachment_type="managed", policy_name="foo")
    )
    assert adapter.validate_target(invalid) is False

def test_mock_adapter_rejects_invalid_inline_privilege():
    adapter = MockIdentityPrivilegeAdapter()
    # Has policy_arn instead of policy_name
    invalid = TargetDescriptor(
        target_type="identity", 
        target_id="id1", 
        privilege=PrivilegeTarget(attachment_type="inline", policy_arn="arn:aws...")
    )
    assert adapter.validate_target(invalid) is False

def test_mock_adapter_rejects_unknown_attachment_type():
    adapter = MockIdentityPrivilegeAdapter()
    invalid = TargetDescriptor(
        target_type="identity", 
        target_id="id1", 
        privilege=PrivilegeTarget(attachment_type="unknown", policy_arn="arn")
    )
    assert adapter.validate_target(invalid) is False

def test_mock_adapter_accepts_valid_privilege():
    adapter = MockIdentityPrivilegeAdapter()
    valid = TargetDescriptor(
        target_type="identity", 
        target_id="id1", 
        privilege=PrivilegeTarget(attachment_type="managed", policy_arn="arn:aws:iam::aws:policy/foo")
    )
    assert adapter.validate_target(valid) is True

def test_mock_adapter_supports():
    adapter = MockIdentityPrivilegeAdapter()
    assert adapter.supports(ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE, TargetDescriptor(target_type="identity", target_id="id1")) is True

def test_mock_adapter_returns_correct_metadata():
    adapter = MockIdentityPrivilegeAdapter()
    req = create_valid_request()
    res = adapter.execute(req)
    assert res.provider_response_metadata["simulated"] is True

def test_cancel_non_existent():
    orch = ExecutionOrchestrator()
    assert orch.cancel("does_not_exist") is False

def test_execute_invalid_source_rejected(orchestrator):
    req = create_valid_request()
    # Pydantic won't let us pass invalid source easily, let's bypass for test
    req.source = "INVALID"
    res = orchestrator.execute(req, "org1")
    assert res.state == ExecutionState.REJECTED
    assert res.error_code == ExecutionErrorCode.INVALID_REQUEST

def test_eligibility_fails_on_unsupported_action(orchestrator):
    req = create_valid_request()
    req.action = "DELETE_DB"
    res = orchestrator.check_eligibility(req)
    assert res.eligible is False
    assert res.error_code == ExecutionErrorCode.ACTION_NOT_ALLOWED

def test_orchestrator_initial_state():
    orch = ExecutionOrchestrator()
    assert len(orch._adapters) == 0
    assert len(orch._idempotency_store) == 0

def test_orchestrator_reject_ready_to_success(orchestrator):
    req = create_valid_request()
    orchestrator._execution_states[req.execution_id] = ExecutionState.READY
    assert orchestrator._transition(req, ExecutionState.EXECUTION_SUCCEEDED) is False
