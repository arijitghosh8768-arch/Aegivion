import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone

from security.engine.execution_contract import (
    ExecutionRequest, TargetDescriptor, ExecutionAction,
    ExecutionSource, PrivilegeTarget, PrivilegeExpectedState
)
from security.engine.response_safety_policy import PolicyDecision
from security.engine.aws_verification_engine import VerificationResult, VerificationStatus
from security.engine.twin_reconciliation_engine import (
    TwinReconciliationEngine, SecurityDigitalTwinAdapter, SecurityChangeRecord
)

class MockTwinAdapter(SecurityDigitalTwinAdapter):
    def __init__(self):
        self.identities = {}
        self.changes = []
        
    def get_identity(self, target_id: str, organization_id: str):
        identity = self.identities.get(target_id)
        if identity and identity.get("organization_id") == organization_id:
            return identity
        return None
        
    def update_identity(self, target_id: str, organization_id: str, updates: dict):
        identity = self.get_identity(target_id, organization_id)
        if identity:
            identity.update(updates)
            
    def record_change(self, change: SecurityChangeRecord):
        self.changes.append(change)

def create_valid_request(override=None):
    base = {
        "organization_id": "org1",
        "requested_by": "admin",
        "source": ExecutionSource.SYSTEM,
        "finding_id": "f1",
        "action": ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE,
        "target": TargetDescriptor(
            target_type="identity", 
            target_id="arn:aws:iam::123456789012:role/TestRole",
            provider="aws",
            cloud_account_id="123456789012",
            identity_type="role",
            privilege=PrivilegeTarget(
                attachment_type="managed",
                policy_arn="arn:aws:iam::aws:policy/AdministratorAccess"
            ),
            expected_privilege_state=PrivilegeExpectedState(attached=True)
        ),
        "policy_decision": PolicyDecision.ALLOW,
        "policy_version": "1.0",
        "policy_evaluated_at": datetime.now(timezone.utc),
        "approval_required": False,
        "idempotency_key": "key1"
    }
    if override:
        base.update(override)
    return ExecutionRequest(**base)

def create_verified_result():
    return VerificationResult(
        status=VerificationStatus.VERIFIED,
        reason="Verified absent",
        verified_at=datetime.now(timezone.utc)
    )

def test_reconciliation_fails_if_not_verified():
    adapter = MockTwinAdapter()
    engine = TwinReconciliationEngine(adapter)
    
    req = create_valid_request()
    res = create_verified_result()
    res.status = VerificationStatus.FAILED
    
    rec = engine.reconcile(req, res)
    assert rec.reconciled is False
    assert "verification status is FAILED" in rec.reason

def test_reconciliation_fails_unsupported_action():
    adapter = MockTwinAdapter()
    engine = TwinReconciliationEngine(adapter)
    
    req = create_valid_request()
    object.__setattr__(req, 'action', "UNSUPPORTED")
    res = create_verified_result()
    
    rec = engine.reconcile(req, res)
    assert rec.reconciled is False
    assert "Unsupported action" in rec.reason

def test_reconciliation_fails_missing_twin_identity():
    adapter = MockTwinAdapter()
    engine = TwinReconciliationEngine(adapter)
    
    req = create_valid_request()
    res = create_verified_result()
    
    rec = engine.reconcile(req, res)
    assert rec.reconciled is False
    assert "not found in Digital Twin" in rec.reason

def test_reconciliation_skips_already_consistent_twin():
    adapter = MockTwinAdapter()
    adapter.identities["arn:aws:iam::123456789012:role/TestRole"] = {
        "organization_id": "org1",
        "privileges": [] # AdministratorAccess is already absent!
    }
    engine = TwinReconciliationEngine(adapter)
    
    req = create_valid_request()
    res = create_verified_result()
    
    rec = engine.reconcile(req, res)
    assert rec.reconciled is True
    assert "already consistent" in rec.reason
    assert len(rec.changes) == 0

def test_reconciliation_happy_path_managed_policy():
    adapter = MockTwinAdapter()
    adapter.identities["arn:aws:iam::123456789012:role/TestRole"] = {
        "organization_id": "org1",
        "privileges": [
            {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess", "type": "managed"},
            {"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "type": "managed"}
        ]
    }
    engine = TwinReconciliationEngine(adapter)
    
    req = create_valid_request()
    res = create_verified_result()
    
    rec = engine.reconcile(req, res)
    assert rec.reconciled is True
    
    # Verify Twin updated
    identity = adapter.identities["arn:aws:iam::123456789012:role/TestRole"]
    assert len(identity["privileges"]) == 1
    assert identity["privileges"][0]["policy_arn"] == "arn:aws:iam::aws:policy/ReadOnlyAccess"
    assert "last_seen_at" in identity
    
    # Verify Audit Record
    assert len(adapter.changes) == 1
    change = adapter.changes[0]
    assert change.change_type == "PRIVILEGE_REMOVED"
    assert change.target_id == "arn:aws:iam::123456789012:role/TestRole"
    assert change.organization_id == "org1"
    assert len(change.old_value) == 2
    assert len(change.new_value) == 1

def test_reconciliation_happy_path_inline_policy():
    adapter = MockTwinAdapter()
    adapter.identities["arn:aws:iam::123456789012:role/TestRole"] = {
        "organization_id": "org1",
        "privileges": [
            {"policy_name": "AegivionTemporaryAdminPolicy", "type": "inline"}
        ]
    }
    engine = TwinReconciliationEngine(adapter)
    
    req = create_valid_request()
    req.target.privilege = PrivilegeTarget(attachment_type="inline", policy_name="AegivionTemporaryAdminPolicy")
    res = create_verified_result()
    
    rec = engine.reconcile(req, res)
    assert rec.reconciled is True
    
    identity = adapter.identities["arn:aws:iam::123456789012:role/TestRole"]
    assert len(identity["privileges"]) == 0
    assert len(adapter.changes) == 1

def test_reconciliation_respects_tenant_isolation():
    adapter = MockTwinAdapter()
    # The identity exists, but belongs to org2!
    adapter.identities["arn:aws:iam::123456789012:role/TestRole"] = {
        "organization_id": "org2",
        "privileges": [
            {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess", "type": "managed"}
        ]
    }
    engine = TwinReconciliationEngine(adapter)
    
    req = create_valid_request()
    res = create_verified_result()
    
    rec = engine.reconcile(req, res)
    assert rec.reconciled is False
    assert "not found in Digital Twin" in rec.reason
    assert len(adapter.changes) == 0
