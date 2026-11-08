import pytest
import uuid
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.models.organization import Organization
from app.models.user import User
from app.models.role import Role
from app.models.organization_member import OrganizationMember

@pytest.fixture
def auth_client():
    db = next(get_db())
    org = Organization(name="Cloud Account Test Org", slug=f"ca-org-{uuid.uuid4().hex[:6]}")
    db.add(org)
    db.flush()

    role = db.query(Role).filter(Role.name == "organization_admin").first()
    if not role:
        role = Role(name="organization_admin", organization_id=org.id)
        db.add(role)
        db.flush()

    user = User(
        email=f"cloud_tester_{uuid.uuid4().hex[:6]}@example.com",
        first_name="Cloud",
        last_name="Admin",
        password_hash="fakehash",
        status="active",
        organization_id=org.id,
        role_id=role.id
    )
    db.add(user)
    db.flush()

    member = OrganizationMember(user_id=user.id, organization_id=org.id, role="ORG_ADMIN")
    db.add(member)
    db.commit()

    from app.core.security import SecurityService
    token = SecurityService().create_access_token(user_id=str(user.id), org_id=str(org.id), role="organization_admin")

    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token}"})

    yield {
        "client": client,
        "org_id": str(org.id),
        "db": db
    }

    try:
        db.delete(org)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

def test_add_cloud_account_with_iam_role(auth_client):
    """Verify backend accepts role_arn and external_id, calls STS caller identity, and saves account."""
    client = auth_client["client"]

    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_session = MagicMock()
    mock_session.client.return_value = mock_sts

    with patch("app.cloud.aws.client.get_aws_session", return_value=mock_session), \
         patch("app.cloud.aws.sync.AWSCloudSync.run_sync", return_value=True), \
         patch("app.api.v1.cloud_accounts.supabase.table") as mock_table:

        mock_insert = MagicMock()
        mock_insert.execute.return_value = MagicMock(data=[{
            "id": "acc-uuid-1",
            "name": "Prod AWS Account",
            "provider": "aws",
            "provider_account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/AegivionScanner",
            "external_id": "aegivion-ext-12345"
        }])
        mock_table.return_value.insert.return_value = mock_insert

        payload = {
            "name": "Prod AWS Account",
            "provider": "aws",
            "role_arn": "arn:aws:iam::123456789012:role/AegivionScanner",
            "external_id": "aegivion-ext-12345"
        }

        res = client.post("/api/v1/cloud-accounts", json=payload)
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["provider_account_id"] == "123456789012"
        assert data["status"] == "HEALTHY"

