import pytest
import uuid
import csv
import io
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.models.organization import Organization
from app.models.user import User
from app.models.role import Role
from app.models.cloud import CloudAccount
from app.models.finding import Finding
from app.core.security import SecurityService

@pytest.fixture
def setup_billing_tenant():
    db = next(get_db())
    org = Organization(name="SaaS Limit Org", slug=f"saas-lim-{uuid.uuid4().hex[:6]}", subscription_plan="free")
    db.add(org)
    db.flush()

    role = db.query(Role).filter(Role.name == "organization_admin").first()
    if not role:
        role = Role(name="organization_admin", organization_id=org.id)
        db.add(role)
        db.flush()

    user = User(
        email=f"saas_user_{uuid.uuid4().hex[:6]}@example.com",
        first_name="SaaS",
        last_name="Tester",
        password_hash="pw_hash",
        status="active",
        organization_id=org.id,
        role_id=role.id
    )
    db.add(user)
    db.flush()

    from app.models.organization_member import OrganizationMember
    member = OrganizationMember(user_id=user.id, organization_id=org.id, role="ORG_ADMIN")
    db.add(member)

    # Add a sample finding for report export
    finding = Finding(
        organization_id=org.id,
        rule_id="AWS-S3-001",
        rule_name="S3 Public Access",
        resource_id="tenant-vault-1",
        resource_name="tenant-vault-1",
        resource_type="s3_bucket",
        cloud_provider="aws",
        title="Public bucket exposed",
        description="Public access block disabled",
        severity="critical",
        status="open",
        source="cspm",
        fingerprint=f"{org.id}:AWS-S3-001:tenant-vault-1"
    )
    db.add(finding)
    db.commit()

    token = SecurityService().create_access_token(user_id=str(user.id), org_id=str(org.id), role="organization_admin")
    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token}"})

    yield {
        "client": client,
        "org_id": org.id,
        "db": db
    }

    try:
        db.delete(org)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

def test_billing_usage_endpoint(setup_billing_tenant):
    client = setup_billing_tenant["client"]
    res = client.get("/api/v1/billing/usage")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["success"] is True
    assert data["subscription_plan"] == "free"
    assert data["plan_details"]["max_cloud_accounts"] == 1
    assert data["usage"]["findings"]["current"] >= 1

def test_cloud_account_limit_enforcement_on_free_tier(setup_billing_tenant):
    client = setup_billing_tenant["client"]
    db = setup_billing_tenant["db"]
    org_id = setup_billing_tenant["org_id"]

    # Insert 1 cloud account directly into DB (reaching the limit of 1 for Free tier)
    existing_acc = CloudAccount(
        name="Existing AWS Acc",
        provider="AWS",
        organization_id=org_id,
        role_arn="arn:aws:iam::111111111111:role/ExistingScanner",
        external_id="ext-1"
    )
    db.add(existing_acc)
    db.commit()

    # Attempt to connect a second account -> Expect HTTP 403 Forbidden
    payload = {
        "name": "Second AWS Acc",
        "provider": "aws",
        "role_arn": "arn:aws:iam::222222222222:role/SecondScanner",
        "external_id": "ext-2"
    }

    res = client.post("/api/v1/cloud-accounts", json=payload)
    assert res.status_code == 403
    assert "Subscription limit reached" in res.json()["detail"]

def test_billing_upgrade_endpoint(setup_billing_tenant):
    client = setup_billing_tenant["client"]
    res = client.post("/api/v1/billing/upgrade", json={"tier": "enterprise"})
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["subscription_plan"] == "enterprise"
    assert data["plan_details"]["max_cloud_accounts"] == 9999

    # Verify usage reflects updated limits
    usage_res = client.get("/api/v1/billing/usage")
    assert usage_res.json()["subscription_plan"] == "enterprise"

def test_findings_csv_export(setup_billing_tenant):
    client = setup_billing_tenant["client"]
    res = client.get("/api/v1/reports/export?format=csv")
    assert res.status_code == 200
    assert res.headers["content-type"] == "text/csv; charset=utf-8"
    assert "aegivion_findings_report.csv" in res.headers["content-disposition"]

    reader = csv.reader(io.StringIO(res.text))
    rows = list(reader)
    header = rows[0]
    assert "rule_id" in header
    assert "resource_id" in header
    assert "severity" in header

    # At least the header and the inserted finding row
    assert len(rows) >= 2
    assert any("AWS-S3-001" in row for row in rows)

