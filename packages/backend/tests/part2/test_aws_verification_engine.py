import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone
import botocore.exceptions

from security.engine.execution_contract import (
    ExecutionRequest, TargetDescriptor, ExecutionAction,
    ExecutionSource, PrivilegeTarget, PrivilegeExpectedState
)
from security.engine.response_safety_policy import PolicyDecision
from security.engine.aws_verification_engine import AWSVerificationEngine, VerificationStatus

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
        "idempotency_key": "key1",
        "dry_run": False
    }
    if override:
        base.update(override)
    return ExecutionRequest(**base)

@pytest.fixture
def mock_session_factory():
    def factory(org_id, account_id):
        session = MagicMock()
        client = MagicMock()
        
        def mock_paginator(operation_name):
            paginator = MagicMock()
            if operation_name == 'list_attached_role_policies':
                paginator.paginate.return_value = [{'AttachedPolicies': []}]
            elif operation_name == 'list_role_policies':
                paginator.paginate.return_value = [{'PolicyNames': []}]
            return paginator
            
        client.get_paginator.side_effect = mock_paginator
        session.client.return_value = client
        return session
    return factory

def test_unsupported_action(mock_session_factory):
    engine = AWSVerificationEngine(mock_session_factory)
    req = create_valid_request()
    object.__setattr__(req, 'action', "UNSUPPORTED")
    res = engine.verify(req)
    assert res.status == VerificationStatus.INSUFFICIENT_EVIDENCE

def test_missing_expected_state(mock_session_factory):
    engine = AWSVerificationEngine(mock_session_factory)
    req = create_valid_request()
    req.target.expected_privilege_state = None
    res = engine.verify(req)
    assert res.status == VerificationStatus.INSUFFICIENT_EVIDENCE

def test_happy_path_managed_policy_removed(mock_session_factory):
    engine = AWSVerificationEngine(mock_session_factory)
    req = create_valid_request()
    res = engine.verify(req)
    # The default mock has empty attached policies, which means success!
    assert res.status == VerificationStatus.VERIFIED
    assert res.provider_metadata["actual_attached"] is False

def test_happy_path_inline_policy_removed(mock_session_factory):
    engine = AWSVerificationEngine(mock_session_factory)
    req = create_valid_request()
    req.target.privilege = PrivilegeTarget(attachment_type="inline", policy_name="AegivionTemporaryAdminPolicy")
    res = engine.verify(req)
    assert res.status == VerificationStatus.VERIFIED
    assert res.provider_metadata["actual_attached"] is False

def test_verification_failed_managed_policy_still_attached():
    def factory(org, acc):
        session = MagicMock()
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{'AttachedPolicies': [{'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}]}]
        client.get_paginator.return_value = paginator
        session.client.return_value = client
        return session
    
    engine = AWSVerificationEngine(factory)
    req = create_valid_request()
    res = engine.verify(req)
    assert res.status == VerificationStatus.FAILED
    assert res.provider_metadata["actual_attached"] is True

def test_verification_failed_inline_policy_still_attached():
    def factory(org, acc):
        session = MagicMock()
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{'PolicyNames': ['AegivionTemporaryAdminPolicy']}]
        client.get_paginator.return_value = paginator
        session.client.return_value = client
        return session
    
    engine = AWSVerificationEngine(factory)
    req = create_valid_request()
    req.target.privilege = PrivilegeTarget(attachment_type="inline", policy_name="AegivionTemporaryAdminPolicy")
    res = engine.verify(req)
    assert res.status == VerificationStatus.FAILED
    assert res.provider_metadata["actual_attached"] is True

def test_drift_detected_role_deleted():
    def factory(org, acc):
        session = MagicMock()
        client = MagicMock()
        def mock_paginator(operation_name):
            raise botocore.exceptions.ClientError({"Error": {"Code": "NoSuchEntity"}}, operation_name)
        client.get_paginator.side_effect = mock_paginator
        session.client.return_value = client
        return session
    
    engine = AWSVerificationEngine(factory)
    req = create_valid_request()
    res = engine.verify(req)
    assert res.status == VerificationStatus.DRIFT_DETECTED
    assert "Role no longer exists" in res.reason

def test_aws_api_error_returns_provider_error():
    def factory(org, acc):
        session = MagicMock()
        client = MagicMock()
        def mock_paginator(operation_name):
            raise botocore.exceptions.ClientError({"Error": {"Code": "AccessDenied"}}, operation_name)
        client.get_paginator.side_effect = mock_paginator
        session.client.return_value = client
        return session
    
    engine = AWSVerificationEngine(factory)
    req = create_valid_request()
    res = engine.verify(req)
    assert res.status == VerificationStatus.PROVIDER_ERROR

def test_dry_run_bypasses_live_aws_query(mock_session_factory):
    session = mock_session_factory("org", "123")
    engine = AWSVerificationEngine(lambda o, a: session)
    req = create_valid_request({"dry_run": True})
    res = engine.verify(req)
    assert res.status == VerificationStatus.VERIFIED
    session.client().get_paginator.assert_not_called()
    assert res.provider_metadata["simulated"] is True

def test_read_only_no_mutation_methods_called(mock_session_factory):
    session = mock_session_factory("org1", "123456789012")
    engine = AWSVerificationEngine(lambda o, a: session)
    req = create_valid_request()
    engine.verify(req)
    
    session.client().get_paginator.assert_called_once()
    session.client().detach_role_policy.assert_not_called()
    session.client().delete_role_policy.assert_not_called()
