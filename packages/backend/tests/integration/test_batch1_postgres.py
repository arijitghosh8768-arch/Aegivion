import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.models.organization import Organization
from app.models.role import Role
from app.models.user import User, UserStatus
from app.models.organization_member import OrganizationMember, OrgRole, MemberStatus
from app.models.auth_session import AuthSession
from app.models.invitation import Invitation
from app.repositories.auth_repository import AuthRepository

import os
from dotenv import load_dotenv, dotenv_values
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
test_env = dotenv_values(os.path.join(os.path.dirname(__file__), "..", "..", ".env.test"))

PG_URL = os.getenv("TEST_DATABASE_URL") or test_env.get("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
if PG_URL and PG_URL.startswith("postgresql://"):
    PG_URL = PG_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

@pytest.fixture(scope="module")
def pg_session():
    if not HAS_PSYCOPG2:
        pytest.skip("psycopg2 driver not installed in this environment")
    try:
        engine = create_engine(PG_URL)
        with engine.connect() as conn:
            pass
    except Exception as e:
        pytest.skip(f"PostgreSQL not reachable: {e}")

    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.rollback()
    session.close()

def test_organization_crud(pg_session):
    slug = f"org-{uuid.uuid4().hex[:8]}"
    org = Organization(name="Test Org", slug=slug)
    pg_session.add(org)
    pg_session.commit()

    queried = pg_session.query(Organization).filter(Organization.id == org.id).first()
    assert queried is not None
    assert queried.slug == slug

    queried.name = "Updated Org"
    pg_session.commit()
    refreshed = pg_session.query(Organization).filter(Organization.id == org.id).first()
    assert refreshed.name == "Updated Org"

    pg_session.delete(refreshed)
    pg_session.commit()
    assert pg_session.query(Organization).filter(Organization.id == org.id).first() is None

def test_user_and_role_crud_with_fk(pg_session):
    org_slug = f"org-u-{uuid.uuid4().hex[:8]}"
    org = Organization(name="User Org", slug=org_slug)
    pg_session.add(org)
    pg_session.flush()

    role = Role(name=f"role-{uuid.uuid4().hex[:6]}", organization_id=org.id)
    pg_session.add(role)
    pg_session.flush()

    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    user = User(
        email=email,
        first_name="Alice",
        last_name="Smith",
        password_hash="hashed_pw_test",
        organization_id=org.id,
        role_id=role.id
    )
    user.set_password("SecurePassword123!")
    pg_session.add(user)
    pg_session.commit()

    assert user.verify_password("SecurePassword123!") is True
    assert user.verify_password("WrongPassword") is False

    queried_user = pg_session.query(User).filter(User.id == user.id).first()
    assert queried_user is not None
    assert queried_user.email == email
    assert queried_user.organization.id == org.id
    assert queried_user.role.id == role.id

    # Cleanup org (cascades user and role)
    pg_session.delete(org)
    pg_session.commit()
    assert pg_session.query(User).filter(User.id == user.id).first() is None
    assert pg_session.query(Role).filter(Role.id == role.id).first() is None

def test_membership_and_session_crud(pg_session):
    org = Organization(name="Member Org", slug=f"org-m-{uuid.uuid4().hex[:8]}")
    pg_session.add(org)
    pg_session.flush()

    role = Role(name=f"role-m-{uuid.uuid4().hex[:6]}", organization_id=org.id)
    pg_session.add(role)
    pg_session.flush()

    user = User(
        email=f"member-{uuid.uuid4().hex[:8]}@example.com",
        first_name="Bob",
        last_name="Jones",
        password_hash="pw",
        organization_id=org.id,
        role_id=role.id
    )
    pg_session.add(user)
    pg_session.flush()

    # Membership
    member = OrganizationMember(
        user_id=user.id,
        organization_id=org.id,
        role=OrgRole.ORG_ADMIN.value,
        status=MemberStatus.ACTIVE.value
    )
    pg_session.add(member)

    # Session
    sess = AuthSession(
        user_id=user.id,
        session_token_hash="hash_token_12345",
        last_used_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1)
    )
    pg_session.add(sess)
    pg_session.commit()

    assert member.id is not None
    assert sess.is_active() is True

    # Cleanup
    pg_session.delete(org)
    pg_session.commit()
    assert pg_session.query(OrganizationMember).filter(OrganizationMember.id == member.id).first() is None
    assert pg_session.query(AuthSession).filter(AuthSession.id == sess.id).first() is None

def test_invitation_crud(pg_session):
    org = Organization(name="Invite Org", slug=f"org-i-{uuid.uuid4().hex[:8]}")
    pg_session.add(org)
    pg_session.flush()

    inv = Invitation(
        org_id=org.id,
        email="invitee@example.com",
        status="PENDING"
    )
    pg_session.add(inv)
    pg_session.commit()

    queried = pg_session.query(Invitation).filter(Invitation.id == inv.id).first()
    assert queried is not None
    assert queried.token == inv.token
    assert queried.email == "invitee@example.com"

    pg_session.delete(org)
    pg_session.commit()
    assert pg_session.query(Invitation).filter(Invitation.id == inv.id).first() is None

def test_unique_constraint_enforcement(pg_session):
    slug = f"unique-org-{uuid.uuid4().hex[:8]}"
    org1 = Organization(name="Org 1", slug=slug)
    pg_session.add(org1)
    pg_session.commit()

    org2 = Organization(name="Org 2", slug=slug)
    pg_session.add(org2)
    with pytest.raises(IntegrityError):
        pg_session.commit()
    pg_session.rollback()

    pg_session.delete(org1)
    pg_session.commit()

def test_transaction_rollback(pg_session):
    slug = f"rollback-{uuid.uuid4().hex[:8]}"
    org = Organization(name="Rollback Org", slug=slug)
    pg_session.add(org)
    pg_session.flush()

    # Rollback before commit
    pg_session.rollback()
    assert pg_session.query(Organization).filter(Organization.slug == slug).first() is None

def test_auth_repository_on_postgres(pg_session):
    auth_repo = AuthRepository(pg_session)

    org = Organization(name="Auth Repo Org", slug=f"org-ar-{uuid.uuid4().hex[:8]}")
    pg_session.add(org)
    pg_session.flush()

    role = Role(name=f"role-ar-{uuid.uuid4().hex[:6]}", organization_id=org.id)
    pg_session.add(role)
    pg_session.flush()

    email = f"authrepo-{uuid.uuid4().hex[:8]}@example.com"
    user = User(
        email=email,
        first_name="Auth",
        last_name="User",
        password_hash="secret_hash",
        organization_id=org.id,
        role_id=role.id
    )
    pg_session.add(user)
    pg_session.commit()

    found_by_email = auth_repo.get_user_by_email(email)
    assert found_by_email is not None
    assert str(found_by_email.id) == str(user.id)

    found_by_id = auth_repo.get_user_by_id(str(user.id))
    assert found_by_id is not None
    assert found_by_id.email == email

    pg_session.delete(org)
    pg_session.commit()
def test_tenant_isolation_user_access(pg_session):
    # Org A
    org_a = Organization(name="Tenant A", slug=f"tenant-a-{uuid.uuid4().hex[:8]}")
    pg_session.add(org_a)
    pg_session.flush()

    role_a = Role(name=f"role-a-{uuid.uuid4().hex[:6]}", organization_id=org_a.id)
    pg_session.add(role_a)
    pg_session.flush()

    user_a = User(
        email=f"usera-{uuid.uuid4().hex[:8]}@example.com",
        first_name="User",
        last_name="A",
        password_hash="hash",
        organization_id=org_a.id,
        role_id=role_a.id
    )
    pg_session.add(user_a)

    # Org B
    org_b = Organization(name="Tenant B", slug=f"tenant-b-{uuid.uuid4().hex[:8]}")
    pg_session.add(org_b)
    pg_session.flush()

    role_b = Role(name=f"role-b-{uuid.uuid4().hex[:6]}", organization_id=org_b.id)
    pg_session.add(role_b)
    pg_session.flush()

    user_b = User(
        email=f"userb-{uuid.uuid4().hex[:8]}@example.com",
        first_name="User",
        last_name="B",
        password_hash="hash",
        organization_id=org_b.id,
        role_id=role_b.id
    )
    pg_session.add(user_b)
    pg_session.commit()

    # Query for Org A's users must reject or not include Org B's users
    org_a_users = pg_session.query(User).filter(User.organization_id == org_a.id).all()
    assert len(org_a_users) == 1
    assert org_a_users[0].id == user_a.id
    assert all(u.organization_id == org_a.id for u in org_a_users)

    # Cross-tenant query assertion
    cross_tenant_lookup = pg_session.query(User).filter(
        User.id == user_b.id,
        User.organization_id == org_a.id
    ).first()
    assert cross_tenant_lookup is None

    # Cleanup
    pg_session.delete(org_a)
    pg_session.delete(org_b)
    pg_session.commit()
