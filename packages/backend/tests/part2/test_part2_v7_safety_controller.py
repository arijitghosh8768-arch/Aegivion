import pytest
from datetime import datetime, timezone
import os
from security.engine.execution_contract import ExecutionRequest, PrivilegeTarget, PrivilegeExpectedState
from security.engine.response_safety_policy import PolicyDecision
from security.engine.safety_controller import SafetyController, SafetyDecision
from security.engine.execution_contract import ApprovalStatus

@pytest.fixture
def base_request():
    from security.engine.execution_contract import TargetDescriptor
    return ExecutionRequest(
        organization_id="tenant-123",
        action="RESTRICT_IDENTITY_PRIVILEGE",
        target_id="user-1",
        privilege_target=PrivilegeTarget(attachment_type="inline"),
        privilege_expected_state=PrivilegeExpectedState(must_be_attached=False, must_be_detached=True),
        justification="Test",
        requested_by="System",
        source="SYSTEM",
        finding_id="find-1",
        target=TargetDescriptor(target_id="user-1", target_type="USER", provider="aws"),
        policy_decision=PolicyDecision.ALLOW,
        policy_version="1.0",
        policy_evaluated_at=datetime.now(timezone.utc).isoformat(),
        approval_required=False,
        idempotency_key="key-1"
    )

def test_safety_controller_allow(base_request):
    os.environ["AUTONOMOUS_RESPONSE"] = "ENABLED"
    controller = SafetyController()
    result = controller.evaluate(base_request, "tenant-123")
    assert result.decision == SafetyDecision.ALLOW

def test_safety_controller_emergency_stop(base_request):
    os.environ["AUTONOMOUS_RESPONSE"] = "DISABLED"
    controller = SafetyController()
    result = controller.evaluate(base_request, "tenant-123")
    assert result.decision == SafetyDecision.EMERGENCY_STOP

def test_safety_controller_tenant_mismatch(base_request):
    os.environ["AUTONOMOUS_RESPONSE"] = "ENABLED"
    controller = SafetyController()
    result = controller.evaluate(base_request, "tenant-456")
    assert result.decision == SafetyDecision.DENY
    assert "Tenant mismatch" in result.reason

def test_safety_controller_protected_target(base_request):
    os.environ["AUTONOMOUS_RESPONSE"] = "ENABLED"
    controller = SafetyController()
    base_request.target.target_id = "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"
    result = controller.evaluate(base_request, "tenant-123")
    assert result.decision == SafetyDecision.DENY
    assert "critical asset" in result.reason
