import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models.user import User, UserStatus
from app.models.role import Role
from app.core.security import get_current_user
from app.models.org_settings import OrgSettings

router = APIRouter()

def require_superadmin(current_user: dict = Depends(get_current_user)):
    role = current_user.get("role", "").lower()
    if role not in ["superadmin", "super admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to Super Admins."
        )
    return current_user

class CreateOrgRequest(BaseModel):
    name: str

class CreateOrgAdminRequest(BaseModel):
    email: str
    password: str
    org_id: str

@router.get("/orgs")
def list_orgs(db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    orgs = db.query(OrgSettings).all()
    # If no org settings, we can't easily list orgs since orgs don't have a dedicated table yet, 
    # they are inferred or stored in OrgSettings.
    return {"success": True, "data": [{"id": str(o.organization_id or o.id), "name": o.branding.get("company_name", "Unknown Org"), "created_at": o.updated_at} for o in orgs]}

@router.post("/orgs")
def create_org(req: CreateOrgRequest, db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    new_id = uuid.uuid4()
    org_setting = OrgSettings(
        id=new_id,
        organization_id=new_id,
        branding={"company_name": req.name, "logo_url": "", "theme_color": ""},
        security_policy={"require_exception_approval": True, "auto_suppress_non_prod": False}
    )
    db.add(org_setting)
    db.commit()
    return {"success": True, "data": {"id": str(new_id), "name": req.name}}

@router.post("/users")
def create_org_admin(req: CreateOrgAdminRequest, db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    # Check if email exists
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="User with this email already exists.")
    
    # Get or create admin role
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(id=uuid.uuid4(), name="admin", description="Organization Admin")
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)

    # Note: We must explicitly hash the password for email/password login
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_pw = pwd_context.hash(req.password)

    new_user = User(
        email=req.email,
        first_name="Org",
        last_name="Admin",
        password_hash=hashed_pw,
        status=UserStatus.ACTIVE,
        email_verified=True,
        organization_id=uuid.UUID(req.org_id),
        role_id=admin_role.id,
        is_platform_admin=False
    )
    db.add(new_user)
    db.commit()
    return {"success": True, "message": "Org admin created successfully."}

@router.get('/users')
def list_org_admins(db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    users = db.query(User).all()
    orgs = {str(o.organization_id or o.id): o.branding.get('company_name', 'Unknown') for o in db.query(OrgSettings).all()}
    
    data = []
    for u in users:
        # filter only org admins (or just show all users, but let's show users with orgs)
        if u.email != 'superadmin@aegivion.com':
            org_name = orgs.get(str(u.organization_id), 'Unassigned')
            data.append({
                'id': str(u.id),
                'email': u.email,
                'org_name': org_name,
                'created_at': u.created_at if isinstance(u.created_at, str) else (u.created_at.isoformat() if hasattr(u, 'created_at') and u.created_at else None)
            })
    return {'success': True, 'data': data}

