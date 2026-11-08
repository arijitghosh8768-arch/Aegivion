import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.models.remediation import RemediationPlan, RemediationAction, RemediationAuditLog
from app.models.organization import Organization
from app.cloud.aws.remediation_executor import RemediationExecutor

@pytest.fixture
def test_setup():
    db = next(get_db())
    org_id = uuid.uuid4()
    org = Organization(id=org_id, name="Exec Test Org", slug=f"exec-org-{org_id.hex[:8]}")
    db.add(org)
    db.commit()

    admin_user = {
        "id": uuid.uuid4(),
        "organization_id": org_id,
        "role": "organization_admin",
        "email": "admin@aegivion.test"
    }

    yield {
        "db": db,
        "org_id": org_id,
        "admin_user": admin_user
    }

    # Teardown
    try:
        db.delete(org)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

def test_s3_remediation_success_captures_snapshot(test_setup):
    """Verify successful execution captures pre-state snapshot and updates status to COMPLETED."""
    db = test_setup["db"]
    org_id = test_setup["org_id"]

    plan = RemediationPlan(
        organization_id=org_id,
        resource_id="corp-vault-bucket",
        status="APPROVED",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
    )
    db.add(plan)
    db.commit()

    action = RemediationAction(
        plan_id=plan.id,
        organization_id=org_id,
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        parameters={"bucket_name": "corp-vault-bucket", "BlockPublicAcls": True},
        status="PENDING"
    )
    db.add(action)
    db.commit()

    mock_s3 = MagicMock()
    # Pre-state snapshot returns open permissions; second call in verify_remediation returns secured permissions
    mock_s3.get_public_access_block.side_effect = [
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        },
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
    ]
    mock_s3.put_public_access_block.return_value = {
        "ResponseMetadata": {"RequestId": "AWS-REQ-S3-9988"}
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_s3

    with patch("app.cloud.aws.remediation_executor.get_aws_session", return_value=mock_session):
        executor = RemediationExecutor(db=db, plan_id=str(plan.id))
        result = executor.execute_plan()

    assert result["action_status"] == "COMPLETED"
    assert result["aws_request_id"] == "AWS-REQ-S3-9988"
    assert result["rollback_payload"]["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is False

    db.refresh(plan)
    db.refresh(action)
    assert plan.status in ("EXECUTED", "VERIFIED")
    assert action.status == "COMPLETED"
    assert action.aws_request_id == "AWS-REQ-S3-9988"

def test_s3_remediation_idempotent_no_op(test_setup):
    """Verify that if public access block is ALREADY fully enabled, execution is marked NO_OP."""
    db = test_setup["db"]
    org_id = test_setup["org_id"]

    plan = RemediationPlan(
        organization_id=org_id,
        resource_id="already-secure-bucket",
        status="APPROVED",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
    )
    db.add(plan)
    db.commit()

    action = RemediationAction(
        plan_id=plan.id,
        organization_id=org_id,
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        parameters={"bucket_name": "already-secure-bucket", "BlockPublicAcls": True},
        status="PENDING"
    )
    db.add(action)
    db.commit()

    mock_s3 = MagicMock()
    # Pre-state snapshot: Already protected
    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_s3

    with patch("app.cloud.aws.remediation_executor.get_aws_session", return_value=mock_session):
        executor = RemediationExecutor(db=db, plan_id=str(plan.id))
        result = executor.execute_plan()

    assert result["action_status"] == "NO_OP"
    assert result["aws_request_id"] == "IDEMPOTENT_NO_OP"
    # AWS put API call must NOT have been called
    mock_s3.put_public_access_block.assert_not_called()

def test_security_group_remediation_client_error_handling(test_setup):
    """Verify AWS ClientError updates action status to FAILED and records error_message."""
    db = test_setup["db"]
    org_id = test_setup["org_id"]

    plan = RemediationPlan(
        organization_id=org_id,
        resource_id="sg-0123456789abcdef0",
        status="APPROVED",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
    )
    db.add(plan)
    db.commit()

    action = RemediationAction(
        plan_id=plan.id,
        organization_id=org_id,
        action_type="REVOKE_SECURITY_GROUP_INGRESS",
        parameters={
            "group_id": "sg-0123456789abcdef0",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_ip": "0.0.0.0/0"
        },
        status="PENDING"
    )
    db.add(action)
    db.commit()

    mock_ec2 = MagicMock()
    # Mock SG exists with unrestricted SSH
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-0123456789abcdef0",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
                ]
            }
        ]
    }
    # Mock revoke throwing AWS ClientError (e.g. UnauthorizedOperation)
    mock_ec2.revoke_security_group_ingress.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized to perform this operation."}},
        "RevokeSecurityGroupIngress"
    )

    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2

    with patch("app.cloud.aws.remediation_executor.get_aws_session", return_value=mock_session):
        executor = RemediationExecutor(db=db, plan_id=str(plan.id))
        with pytest.raises(RuntimeError) as exc:
            executor.execute_plan()
        assert "You are not authorized" in str(exc.value)

    db.refresh(action)
    assert action.status == "FAILED"
    assert "You are not authorized" in action.error_message

def test_execute_endpoint_rejects_unapproved_plan(test_setup):
    """Endpoint must return 400 Bad Request if plan is PENDING_APPROVAL instead of APPROVED."""
    db = test_setup["db"]
    org_id = test_setup["org_id"]
    admin = test_setup["admin_user"]

    plan = RemediationPlan(
        organization_id=org_id,
        resource_id="unapproved-bucket",
        status="PENDING_APPROVAL",  # Not approved!
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
    )
    db.add(plan)
    db.commit()

    app.dependency_overrides[get_current_user] = lambda: admin
    app.dependency_overrides[get_current_organization] = lambda: org_id
    client = TestClient(app)

    try:
        res = client.post(f"/api/v1/remediation/plans/{plan.id}/execute")
        assert res.status_code == 400
        assert "Plan must be 'APPROVED'" in res.json()["detail"]
    finally:
        app.dependency_overrides.clear()

