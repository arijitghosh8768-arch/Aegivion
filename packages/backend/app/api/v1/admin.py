import uuid
import re
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.database.session import set_session_tenant
from app.models.organization import Organization, SubscriptionPlan
from app.models.user import User, UserStatus
from app.models.role import Role
from app.models.organization_member import OrganizationMember, OrgRole
from app.core.security import get_current_user

router = APIRouter()

def require_superadmin(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    role = (current_user.get("role") or "").lower().replace(" ", "")
    if role != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to Super Admins."
        )
    # Superadmin operates across all tenants in global admin panel
    try:
        set_session_tenant(db, "bypass")
    except Exception:
        pass
    return current_user

class CreateOrgRequest(BaseModel):
    name: str

class CreateOrgAdminRequest(BaseModel):
    email: EmailStr
    password: str
    org_id: str

@router.get("/orgs")
def list_orgs(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_superadmin)
):
    orgs = db.query(Organization).order_by(Organization.created_at.desc()).all()
    data = []
    for o in orgs:
        created_at_val = o.created_at
        if hasattr(created_at_val, "isoformat"):
            created_at_str = created_at_val.isoformat()
        else:
            created_at_str = str(created_at_val) if created_at_val else None

        data.append({
            "id": str(o.id),
            "name": o.name,
            "slug": o.slug,
            "created_at": created_at_str
        })
    return {"success": True, "data": data}

@router.post("/orgs")
def create_org(
    req: CreateOrgRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_superadmin)
):
    org_name = req.name.strip()
    if not org_name:
        raise HTTPException(status_code=400, detail="Organization name is required")

    # Generate slug from name with randomness to prevent collision
    base_slug = re.sub(r"[^a-z0-9]+", "-", org_name.lower()).strip("-") or "org"
    slug = f"{base_slug}-{uuid.uuid4().hex[:6]}"

    new_org = Organization(
        id=uuid.uuid4(),
        name=org_name,
        slug=slug,
        subscription_plan="free",
        is_active=True,
        settings={
            "enabled_cloud_providers": ["aws"],
            "branding": {"company_name": org_name, "logo_url": "", "theme_color": ""}
        }
    )
    db.add(new_org)
    db.commit()
    db.refresh(new_org)

    return {
        "success": True,
        "data": {
            "id": str(new_org.id),
            "name": new_org.name,
            "slug": new_org.slug
        }
    }

@router.post("/users")
def create_org_admin(
    req: CreateOrgAdminRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_superadmin)
):
    try:
        target_org_id = uuid.UUID(req.org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid organization ID format")

    org = db.query(Organization).filter(Organization.id == target_org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check if email exists
    if db.query(User).filter(User.email == req.email.lower().strip()).first():
        raise HTTPException(status_code=400, detail="User with this email already exists.")

    # Get or create admin role
    admin_role = db.query(Role).filter(Role.name.in_(["organization_admin", "admin"])).first()
    if not admin_role:
        admin_role = Role(id=uuid.uuid4(), name="organization_admin", description="Organization Administrator")
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)

    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_pw = pwd_context.hash(req.password)

    new_user = User(
        id=uuid.uuid4(),
        email=req.email.lower().strip(),
        first_name="Org",
        last_name="Admin",
        password_hash=hashed_pw,
        status=UserStatus.ACTIVE,
        email_verified=True,
        organization_id=target_org_id,
        role_id=admin_role.id,
        is_platform_admin=False
    )
    db.add(new_user)

    new_member = OrganizationMember(
        id=uuid.uuid4(),
        user_id=new_user.id,
        organization_id=target_org_id,
        role=OrgRole.ORG_ADMIN
    )
    db.add(new_member)

    db.commit()
    return {"success": True, "message": "Org admin created successfully."}

@router.get("/users")
def list_org_admins(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_superadmin)
):
    # Query users that are admins of organizations (excluding superadmin)
    users = db.query(User).filter(User.email != "superadmin@aegivion.com").all()
    orgs = {o.id: o.name for o in db.query(Organization).all()}
    members = db.query(OrganizationMember).all()
    member_map = {m.user_id: m for m in members}
    roles = {r.id: r.name for r in db.query(Role).all()}

    data = []
    for u in users:
        role_name = (roles.get(u.role_id) or "").lower()
        member_entry = member_map.get(u.id)
        member_role = str(member_entry.role).upper() if member_entry else ""

        # Include if user is admin/org_admin
        if "admin" in role_name or "admin" in member_role.lower():
            org_id = u.organization_id or (member_entry.organization_id if member_entry else None)
            org_name = orgs.get(org_id, "Unassigned")
            created_at_val = u.created_at
            created_at_str = created_at_val.isoformat() if hasattr(created_at_val, "isoformat") else str(created_at_val) if created_at_val else None

            data.append({
                "id": str(u.id),
                "email": u.email,
                "org_name": org_name,
                "role": "ORG_ADMIN",
                "created_at": created_at_str
            })

    return {"success": True, "data": data}

@router.delete("/orgs/{org_id}")
def delete_org(
    org_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_superadmin)
):
    try:
        oid = uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid org ID format")

    org = db.query(Organization).filter(Organization.id == oid).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    db.delete(org)
    db.commit()
    return {"success": True, "message": "Organization deleted"}

@router.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_superadmin)
):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.email == "superadmin@aegivion.com":
        raise HTTPException(status_code=400, detail="Cannot delete superadmin")

    db.delete(user)
    db.commit()
    return {"success": True, "message": "User deleted"}
