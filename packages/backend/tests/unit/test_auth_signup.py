import pytest
import uuid
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.models.organization import Organization
from app.models.user import User
from app.models.organization_member import OrganizationMember

@pytest.fixture
def db_session():
    db = next(get_db())
    yield db
    db.close()

def test_signup_creates_org_user_and_tokens(db_session):
    client = TestClient(app)
    
    unique_suffix = uuid.uuid4().hex[:8]
    email = f"signup_test_{unique_suffix}@example.com"
    org_name = f"Test Corp {unique_suffix}"
    
    payload = {
        "full_name": "Sarah Connor",
        "organization_name": org_name,
        "email": email,
        "password": "Password123!Secure"
    }
    
    response = client.post("/api/v1/auth/signup", json=payload)
    assert response.status_code == 200, response.text
    
    data = response.json()
    assert data["success"] is True
    assert "token" in data and len(data["token"]) > 20
    assert "refresh_token" in data and len(data["refresh_token"]) > 20
    assert data["user"]["email"] == email.lower()
    assert data["user"]["name"] == "Sarah Connor"
    assert data["user"]["role"] == "organization_admin"
    assert data["user"]["organization_name"] == org_name
    
    org_id = uuid.UUID(data["user"]["organization_id"])
    user_id = uuid.UUID(data["user"]["id"])
    
    # Verify records created in DB
    org = db_session.query(Organization).filter(Organization.id == org_id).first()
    assert org is not None
    assert org.name == org_name
    assert org.owner_id == user_id
    
    user = db_session.query(User).filter(User.id == user_id).first()
    assert user is not None
    assert user.email == email.lower()
    assert user.organization_id == org_id
    assert user.first_name == "Sarah"
    assert user.last_name == "Connor"
    assert user.verify_password("Password123!Secure") is True
    
    member = db_session.query(OrganizationMember).filter(
        OrganizationMember.user_id == user_id,
        OrganizationMember.organization_id == org_id
    ).first()
    assert member is not None
    assert member.role == "ORG_ADMIN"

def test_signup_duplicate_email_rejected(db_session):
    client = TestClient(app)
    
    unique_suffix = uuid.uuid4().hex[:8]
    email = f"dupe_{unique_suffix}@example.com"
    
    payload = {
        "full_name": "John Matrix",
        "organization_name": f"Val Verde Corp {unique_suffix}",
        "email": email,
        "password": "StrongPassword999!"
    }
    
    # 1st request: Success
    res1 = client.post("/api/v1/auth/signup", json=payload)
    assert res1.status_code == 200
    
    # 2nd request with same email: 400 Bad Request
    res2 = client.post("/api/v1/auth/signup", json=payload)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]

def test_signup_short_password_rejected():
    client = TestClient(app)
    
    payload = {
        "full_name": "Short Pw User",
        "organization_name": "Insecure Corp",
        "email": f"short_{uuid.uuid4().hex[:6]}@example.com",
        "password": "short"
    }
    
    res = client.post("/api/v1/auth/signup", json=payload)
    assert res.status_code == 400
    assert "at least 8 characters" in res.json()["detail"]
