import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.models.remediation import RemediationPlan, RemediationAction, RemediationAuditLog
from app.models.finding import Finding
from app.models.organization import Organization
from app.cloud.aws.remediation_executor import RemediationExecutor

@pytest.fixture
def test_setup():
    db = next(get_db())
    org_id = uuid.uuid4()
    org = Organization(id=org_id, name="Verify Rollback Org", slug=f"vr-org-{org_id.hex[:8]}")
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

def test_post_execution_verification_marks_finding_resolved(test_setup):
    """
    Test 1:
    Post-execution verification triggers after action executes.
    If the collector/AWS state confirms clean compliance,
    Finding transitions to 'resolved' and Plan transitions to 'VERIFIED'.
    """
    db = test_setup["db"]
    org_id = test_setup["org_id"]

    finding = Finding(
        organization_id=org_id,
        rule_id="AWS-S3-001",
        rule_name="S3 Public Access Block",
        resource_id="secure-archive-bucket",
        resource_name="secure-archive-bucket",
        resource_type="s3_bucket",
        cloud_provider="aws",
        title="Public bucket",
        description="Public bucket detected",
        severity="critical",
        status="open",
        source="cspm",
        fingerprint=f"{org_id}:AWS-S3-001:secure-archive-bucket"
    )
    db.add(finding)
    db.commit()

    plan = RemediationPlan(
        organization_id=org_id,
        finding_id=finding.id,
        resource_id="secure-archive-bucket",
        status="APPROVED",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
    )
    db.add(plan)
    db.commit()

    action = RemediationAction(
        plan_id=plan.id,
        organization_id=org_id,
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        parameters={"bucket_name": "secure-archive-bucket", "BlockPublicAcls": True},
        status="PENDING"
    )
    db.add(action)
    db.commit()

    mock_s3 = MagicMock()
    # 1. First get_public_access_block call: pre-state snapshot (open)
    # 2. Second get_public_access_block call (in verify_remediation): now fully closed!
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
        "ResponseMetadata": {"RequestId": "AWS-REQ-VERIFIED-1"}
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_s3

    with patch("app.cloud.aws.remediation_executor.get_aws_session", return_value=mock_session):
        executor = RemediationExecutor(db=db, plan_id=str(plan.id))
        executor.execute_plan()

    db.refresh(plan)
    db.refresh(finding)
    assert plan.status == "VERIFIED"
    assert finding.status == "resolved"
    assert finding.resolved_at is not None

def test_verification_failure_triggers_automatic_rollback(test_setup):
    """
    Test 2:
    If post-execution verification fails (finding/violation still present in AWS),
    the plan transitions to 'FAILED_VERIFICATION' and triggers automatic rollback!
    """
    db = test_setup["db"]
    org_id = test_setup["org_id"]

    plan = RemediationPlan(
        organization_id=org_id,
        resource_id="stubborn-bucket",
        status="APPROVED",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
    )
    db.add(plan)
    db.commit()

    action = RemediationAction(
        plan_id=plan.id,
        organization_id=org_id,
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        parameters={"bucket_name": "stubborn-bucket", "BlockPublicAcls": True},
        status="PENDING"
    )
    db.add(action)
    db.commit()

    mock_s3 = MagicMock()
    # 1. Pre-state snapshot: open
    # 2. Verification call: STILL OPEN (e.g. AWS SCP or policy prevented change)
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
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        }
    ]
    mock_s3.put_public_access_block.return_value = {"ResponseMetadata": {"RequestId": "REQ-1"}}

    mock_session = MagicMock()
    mock_session.client.return_value = mock_s3

    with patch("app.cloud.aws.remediation_executor.get_aws_session", return_value=mock_session):
        executor = RemediationExecutor(db=db, plan_id=str(plan.id))
        executor.execute_plan()

    db.refresh(plan)
    db.refresh(action)
    # Plan must have automatically rolled back
    assert plan.status == "ROLLED_BACK"
    assert action.status == "ROLLED_BACK"

def test_manual_rollback_endpoint(test_setup):
    """
    Test 3:
    POST /api/v1/remediation/plans/{id}/rollback reads the saved snapshot
    and successfully restores the previous AWS configuration.
    """
    db = test_setup["db"]
    org_id = test_setup["org_id"]
    admin = test_setup["admin_user"]

    plan = RemediationPlan(
        organization_id=org_id,
        resource_id="sg-0123456789abcdef0",
        status="VERIFIED",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
    )
    db.add(plan)
    db.commit()

    action = RemediationAction(
        plan_id=plan.id,
        organization_id=org_id,
        action_type="REVOKE_SECURITY_GROUP_INGRESS",
        parameters={"group_id": "sg-0123456789abcdef0", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ip": "0.0.0.0/0"},
        rollback_payload={
            "group_id": "sg-0123456789abcdef0",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        },
        status="COMPLETED"
    )
    db.add(action)
    db.commit()

    mock_ec2 = MagicMock()
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2

    app.dependency_overrides[get_current_user] = lambda: admin
    app.dependency_overrides[get_current_organization] = lambda: org_id
    client = TestClient(app)

    try:
        with patch("app.cloud.aws.remediation_executor.get_aws_session", return_value=mock_session):
            res = client.post(f"/api/v1/remediation/plans/{plan.id}/rollback")

        assert res.status_code == 200
        data = res.json()
        assert data["plan_status"] == "ROLLED_BACK"
        assert data["action_status"] == "ROLLED_BACK"

        # Verify AWS EC2 authorize_security_group_ingress was called to restore rule!
        mock_ec2.authorize_security_group_ingress.assert_called_once_with(
            GroupId="sg-0123456789abcdef0",
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        )
    finally:
        app.dependency_overrides.clear()

