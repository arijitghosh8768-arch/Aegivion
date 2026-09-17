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
from app.models.organization_member import OrganizationMember, OrgRole

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
        role_id=admin_role.id,
        is_platform_admin=False
    )
    db.add(new_user)
    
    new_member = OrganizationMember(
        user_id=new_user.id,
        organization_id=uuid.UUID(req.org_id),
        role=OrgRole.ORG_ADMIN
    )
    db.add(new_member)
    
    db.commit()

    return {"success": True, "message": "Org admin created successfully."}

@router.get('/users')
def list_org_admins(db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    users = {str(u.id): u for u in db.query(User).all()}
    orgs = {str(o.organization_id or o.id): o.branding.get('company_name', 'Unknown') for o in db.query(OrgSettings).all()}
    members = db.query(OrganizationMember).all()
    roles = {str(r.id): r for r in db.query(Role).all()}
    
    data = []
    
    for m in members:
        u = users.get(str(m.user_id))
        if u and u.email != 'superadmin@aegivion.com':
            role_str = str(m.role).upper()
            if 'ADMIN' in role_str or role_str == 'ORG_ADMIN':
                org_name = orgs.get(str(m.organization_id), 'Unassigned')
                data.append({
                    'id': str(u.id),
                    'email': u.email,
                    'org_name': org_name,
                    'role': m.role,
                    'created_at': u.created_at if isinstance(u.created_at, str) else (u.created_at.isoformat() if hasattr(u, 'created_at') and u.created_at else None)
                })
            
    legacy_user_ids = {str(m.user_id) for m in members}
    for uid, u in users.items():
        if uid not in legacy_user_ids and u.email != 'superadmin@aegivion.com' and getattr(u, 'organization_id', None):
            # Check legacy role_id
            is_admin = False
            r_id = str(u.role_id)
            if r_id.upper() in ['ADMIN', 'ORG_ADMIN']:
                is_admin = True
            else:
                role_obj = roles.get(r_id)
                if role_obj and 'admin' in role_obj.name.lower():
                    is_admin = True
                    
            if is_admin:
                org_name = orgs.get(str(u.organization_id), 'Unassigned')
                data.append({
                    'id': str(u.id),
                    'email': u.email,
                    'org_name': org_name,
                    'role': 'ORG_ADMIN',
                    'created_at': u.created_at if isinstance(u.created_at, str) else (u.created_at.isoformat() if hasattr(u, 'created_at') and u.created_at else None)
                })
            
    return {'success': True, 'data': data}



@router.delete("/orgs/{org_id}")
def delete_org(org_id: str, db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
    try:
        oid = uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid org ID format")
    
    org = db.query(OrgSettings).filter(OrgSettings.id == oid).first()
    if not org:
        org = db.query(OrgSettings).filter(OrgSettings.organization_id == oid).first()
        
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    db.delete(org)
    db.commit()
    return {"success": True, "message": "Organization deleted"}

@router.delete("/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db), current_user: dict = Depends(require_superadmin)):
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
