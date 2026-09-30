import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError

from security.engine.execution_contract import (
    ExecutionRequest, TargetDescriptor, ExecutionAction,
    ExecutionSource, ApprovalStatus, ExecutionResult, ExecutionState
)
from security.engine.response_safety_policy import PolicyDecision

def valid_target():
    return TargetDescriptor(target_type="identity", target_id="id-1")

def test_contract_valid_instantiation():
    req = ExecutionRequest(
        organization_id="org1",
        requested_by="admin",
        source=ExecutionSource.SYSTEM,
        finding_id="f1",
        action=ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE,
        target=valid_target(),
        policy_decision=PolicyDecision.ALLOW,
        policy_version="1.0",
        policy_evaluated_at=datetime.now(timezone.utc),
        approval_required=False,
        idempotency_key="key1"
    )
    assert req.action == ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE

def test_contract_missing_org():
    with pytest.raises(ValidationError):
        ExecutionRequest(
            requested_by="admin",
            source=ExecutionSource.SYSTEM,
            finding_id="f1",
            action=ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE,
            target=valid_target(),
            policy_decision=PolicyDecision.ALLOW,
            policy_version="1.0",
            policy_evaluated_at=datetime.now(timezone.utc),
            approval_required=False,
            idempotency_key="key1"
        )

def test_contract_missing_action():
    with pytest.raises(ValidationError):
        ExecutionRequest(
            organization_id="org1",
            requested_by="admin",
            source=ExecutionSource.SYSTEM,
            finding_id="f1",
            target=valid_target(),
            policy_decision=PolicyDecision.ALLOW,
            policy_version="1.0",
            policy_evaluated_at=datetime.now(timezone.utc),
            approval_required=False,
            idempotency_key="key1"
        )

def test_contract_unsupported_action():
    with pytest.raises(ValidationError):
        ExecutionRequest(
            organization_id="org1",
            requested_by="admin",
            source=ExecutionSource.SYSTEM,
            finding_id="f1",
            action="UNSUPPORTED_ACTION",
            target=valid_target(),
            policy_decision=PolicyDecision.ALLOW,
            policy_version="1.0",
            policy_evaluated_at=datetime.now(timezone.utc),
            approval_required=False,
            idempotency_key="key1"
        )

def test_contract_invalid_target():
    with pytest.raises(ValidationError):
        TargetDescriptor(target_type="identity") # missing target_id

def test_contract_missing_policy_decision():
    with pytest.raises(ValidationError):
        ExecutionRequest(
            organization_id="org1",
            requested_by="admin",
            source=ExecutionSource.SYSTEM,
            finding_id="f1",
            action=ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE,
            target=valid_target(),
            policy_version="1.0",
            policy_evaluated_at=datetime.now(timezone.utc),
            approval_required=False,
            idempotency_key="key1"
        )

def test_contract_invalid_source():
    with pytest.raises(ValidationError):
        ExecutionRequest(
            organization_id="org1",
            requested_by="admin",
            source="INVALID",
            finding_id="f1",
            action=ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE,
            target=valid_target(),
            policy_decision=PolicyDecision.ALLOW,
            policy_version="1.0",
            policy_evaluated_at=datetime.now(timezone.utc),
            approval_required=False,
            idempotency_key="key1"
        )

def test_contract_ai_source_rejected():
    with pytest.raises(ValidationError):
        ExecutionRequest(
            organization_id="org1",
            requested_by="admin",
            source="AI",
            finding_id="f1",
            action=ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE,
            target=valid_target(),
            policy_decision=PolicyDecision.ALLOW,
            policy_version="1.0",
            policy_evaluated_at=datetime.now(timezone.utc),
            approval_required=False,
            idempotency_key="key1"
        )

def test_contract_missing_idempotency_key():
    with pytest.raises(ValidationError):
        ExecutionRequest(
            organization_id="org1",
            requested_by="admin",
            source=ExecutionSource.SYSTEM,
            finding_id="f1",
            action=ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE,
            target=valid_target(),
            policy_decision=PolicyDecision.ALLOW,
            policy_version="1.0",
            policy_evaluated_at=datetime.now(timezone.utc),
            approval_required=False
        )

from security.engine.execution_contract import PrivilegeTarget, PrivilegeExpectedState

def test_contract_privilege_managed_valid():
    tgt = TargetDescriptor(
        target_type="identity",
        target_id="id1",
        privilege=PrivilegeTarget(
            attachment_type="managed",
            policy_arn="arn:aws:iam::aws:policy/foo"
        )
    )
    assert tgt.privilege.attachment_type == "managed"

def test_contract_privilege_inline_valid():
    tgt = TargetDescriptor(
        target_type="identity",
        target_id="id1",
        privilege=PrivilegeTarget(
            attachment_type="inline",
            policy_name="foo-inline"
        )
    )
    assert tgt.privilege.attachment_type == "inline"

def test_contract_privilege_expected_state():
    state = PrivilegeExpectedState(attached=True)
    assert state.attached is True
