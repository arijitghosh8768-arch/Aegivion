import pytest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.models.remediation import RemediationPlan, RemediationAction, RemediationAuditLog
from app.models.finding import Finding
from app.models.organization import Organization

@pytest.fixture
def org_and_user():
    db = next(get_db())
    slug = f"appr-org-{uuid.uuid4().hex[:8]}"
    org = Organization(name="Approval Test Org", slug=slug)
    db.add(org)
    db.commit()

    admin_id = uuid.uuid4()
    viewer_id = uuid.uuid4()

    admin_user = {
        "id": admin_id,
        "organization_id": org.id,
        "role": "organization_admin",
        "email": "admin@aegivion.test"
    }
    viewer_user = {
        "id": viewer_id,
        "organization_id": org.id,
        "role": "viewer",
        "email": "viewer@aegivion.test"
    }

    yield {
        "db": db,
        "org": org,
        "org_id": org.id,
        "admin_user": admin_user,
        "viewer_user": viewer_user
    }

    # Teardown
    try:
        db.delete(org)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

def test_remediation_approval_workflow_success(org_and_user):
    """Admin successfully approves an active, non-expired plan."""
    db = org_and_user["db"]
    org_id = org_and_user["org_id"]
    admin = org_and_user["admin_user"]

    finding = Finding(
        organization_id=org_id,
        rule_id="AWS-S3-001",
        rule_name="S3 Public Access Block",
        resource_id="test-bucket",
        resource_name="test-bucket",
        resource_type="s3_bucket",
        cloud_provider="aws",
        title="Public bucket",
        description="Public bucket detected",
        severity="critical",
        status="open",
        source="cspm",
        fingerprint=f"{org_id}:AWS-S3-001:test-bucket"
    )
    db.add(finding)
    db.commit()

    plan = RemediationPlan(
        organization_id=org_id,
        finding_id=finding.id,
        resource_id="test-bucket",
        status="PENDING_APPROVAL",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
    )
    db.add(plan)
    db.commit()

    # Override dependencies
    app.dependency_overrides[get_current_user] = lambda: admin
    app.dependency_overrides[get_current_organization] = lambda: org_id
    client = TestClient(app)

    try:
        res = client.post(f"/api/v1/remediation/plans/{plan.id}/approve")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "APPROVED"

        # Verify DB audit log created
        audit = db.query(RemediationAuditLog).filter_by(plan_id=plan.id, action="PLAN_APPROVED").first()
        assert audit is not None
    finally:
        app.dependency_overrides.clear()

def test_remediation_approval_fails_when_expired(org_and_user):
    """Approval must fail with 400 when the plan's 2-hour TTL has expired."""
    db = org_and_user["db"]
    org_id = org_and_user["org_id"]
    admin = org_and_user["admin_user"]

    finding = Finding(
        organization_id=org_id,
        rule_id="AWS-S3-001",
        rule_name="S3 Public Access Block",
        resource_id="test-bucket",
        resource_name="test-bucket",
        resource_type="s3_bucket",
        cloud_provider="aws",
        title="Public bucket",
        description="Public bucket detected",
        severity="critical",
        status="open",
        source="cspm",
        fingerprint=f"{org_id}:AWS-S3-001:test-bucket-expired"
    )
    db.add(finding)
    db.commit()

    # Set expires_at in the PAST
    plan = RemediationPlan(
        organization_id=org_id,
        finding_id=finding.id,
        resource_id="test-bucket",
        status="PENDING_APPROVAL",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=10)
    )
    db.add(plan)
    db.commit()

    app.dependency_overrides[get_current_user] = lambda: admin
    app.dependency_overrides[get_current_organization] = lambda: org_id
    client = TestClient(app)

    try:
        res = client.post(f"/api/v1/remediation/plans/{plan.id}/approve")
        assert res.status_code == 400
        assert "Plan has expired" in res.json()["detail"]

        # Check DB status updated to EXPIRED (refresh identity map from DB)
        db.expire_all()
        refreshed = db.query(RemediationPlan).filter_by(id=plan.id).first()
        assert refreshed.status == "EXPIRED"
    finally:
        app.dependency_overrides.clear()

def test_remediation_approval_forbidden_for_viewer(org_and_user):
    """Viewer role must be blocked from approving remediation plans (HTTP 403)."""
    org_id = org_and_user["org_id"]
    viewer = org_and_user["viewer_user"]

    plan_id = uuid.uuid4()
    app.dependency_overrides[get_current_user] = lambda: viewer
    app.dependency_overrides[get_current_organization] = lambda: org_id
    client = TestClient(app)

    try:
        res = client.post(f"/api/v1/remediation/plans/{plan_id}/approve")
        assert res.status_code == 403
        assert "manage_automation" in res.json()["detail"]
    finally:
        app.dependency_overrides.clear()

def test_remediation_rejection_workflow(org_and_user):
    """Admin can reject a proposed plan."""
    db = org_and_user["db"]
    org_id = org_and_user["org_id"]
    admin = org_and_user["admin_user"]

    plan = RemediationPlan(
        organization_id=org_id,
        resource_id="test-bucket",
        status="PENDING_APPROVAL",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
    )
    db.add(plan)
    db.commit()

    app.dependency_overrides[get_current_user] = lambda: admin
    app.dependency_overrides[get_current_organization] = lambda: org_id
    client = TestClient(app)

    try:
        res = client.post(f"/api/v1/remediation/plans/{plan.id}/reject")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "REJECTED"

        audit = db.query(RemediationAuditLog).filter_by(plan_id=plan.id, action="PLAN_REJECTED").first()
        assert audit is not None
    finally:
        app.dependency_overrides.clear()
