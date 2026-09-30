import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone
import botocore.exceptions

from security.engine.execution_contract import (
    ExecutionRequest, TargetDescriptor, ExecutionAction,
    ExecutionSource, PrivilegeTarget, PrivilegeExpectedState
)
from security.engine.response_safety_policy import PolicyDecision
from security.engine.aws_precondition_checker import AWSPreconditionChecker, PreconditionStatus

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

@pytest.fixture
def mock_session_factory():
    def factory(org_id, account_id):
        session = MagicMock()
        client = MagicMock()
        
        def mock_paginator(operation_name):
            paginator = MagicMock()
            if operation_name == 'list_attached_role_policies':
                paginator.paginate.return_value = [{'AttachedPolicies': [{'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}]}]
            elif operation_name == 'list_role_policies':
                paginator.paginate.return_value = [{'PolicyNames': ['AegivionTemporaryAdminPolicy']}]
            return paginator
            
        client.get_paginator.side_effect = mock_paginator
        session.client.return_value = client
        return session
    return factory

def test_unsupported_action(mock_session_factory):
    checker = AWSPreconditionChecker(mock_session_factory)
    # create invalid request bypassing validation for test
    req = create_valid_request()
    # Hack action
    object.__setattr__(req, 'action', "UNSUPPORTED")
    res = checker.check(req)
    assert res.status == PreconditionStatus.FAIL_VALIDATION

def test_missing_expected_state(mock_session_factory):
    checker = AWSPreconditionChecker(mock_session_factory)
    req = create_valid_request()
    req.target.expected_privilege_state = None
    res = checker.check(req)
    assert res.status == PreconditionStatus.FAIL_VALIDATION

def test_happy_path_managed_policy_attached(mock_session_factory):
    checker = AWSPreconditionChecker(mock_session_factory)
    req = create_valid_request()
    res = checker.check(req)
    assert res.status == PreconditionStatus.PASS
    assert res.provider_metadata["actual_attached"] is True

def test_happy_path_inline_policy_attached(mock_session_factory):
    checker = AWSPreconditionChecker(mock_session_factory)
    req = create_valid_request()
    req.target.privilege = PrivilegeTarget(attachment_type="inline", policy_name="AegivionTemporaryAdminPolicy")
    res = checker.check(req)
    assert res.status == PreconditionStatus.PASS
    assert res.provider_metadata["actual_attached"] is True

def test_toctou_drift_managed_policy_missing():
    def factory(org, acc):
        session = MagicMock()
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{'AttachedPolicies': []}]
        client.get_paginator.return_value = paginator
        session.client.return_value = client
        return session
    
    checker = AWSPreconditionChecker(factory)
    req = create_valid_request()
    res = checker.check(req)
    assert res.status == PreconditionStatus.FAIL_DRIFT
    assert res.provider_metadata["actual_attached"] is False

def test_toctou_drift_inline_policy_missing():
    def factory(org, acc):
        session = MagicMock()
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{'PolicyNames': []}]
        client.get_paginator.return_value = paginator
        session.client.return_value = client
        return session
    
    checker = AWSPreconditionChecker(factory)
    req = create_valid_request()
    req.target.privilege = PrivilegeTarget(attachment_type="inline", policy_name="AegivionTemporaryAdminPolicy")
    res = checker.check(req)
    assert res.status == PreconditionStatus.FAIL_DRIFT
    assert res.provider_metadata["actual_attached"] is False

def test_toctou_drift_role_deleted():
    def factory(org, acc):
        session = MagicMock()
        client = MagicMock()
        def mock_paginator(operation_name):
            raise botocore.exceptions.ClientError({"Error": {"Code": "NoSuchEntity"}}, operation_name)
        client.get_paginator.side_effect = mock_paginator
        session.client.return_value = client
        return session
    
    checker = AWSPreconditionChecker(factory)
    req = create_valid_request()
    res = checker.check(req)
    assert res.status == PreconditionStatus.FAIL_DRIFT
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
    
    checker = AWSPreconditionChecker(factory)
    req = create_valid_request()
    res = checker.check(req)
    assert res.status == PreconditionStatus.FAIL_PROVIDER_ERROR

def test_read_only_no_mutation_methods_called(mock_session_factory):
    # Verify the mock doesn't get mutating methods called
    session = mock_session_factory("org1", "123456789012")
    checker = AWSPreconditionChecker(lambda o, a: session)
    req = create_valid_request()
    checker.check(req)
    
    # Assert get_paginator was called, but not detach/delete
    session.client().get_paginator.assert_called_once()
    session.client().detach_role_policy.assert_not_called()
    session.client().delete_role_policy.assert_not_called()
