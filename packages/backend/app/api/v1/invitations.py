import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.invitation import Invitation
from app.models.organization import Organization
from app.models.role import Role
from app.models.audit_log import AuditLog, AuditAction
from app.core.security import get_current_user
from app.api.deps import require_permission
from app.core.tenant import get_current_organization
from app.repositories import OrganizationRepository, InvitationRepository

router = APIRouter()

class InviteRequest(BaseModel):
    email: EmailStr
    role: str

def _resolve_role_id(db: Session, role_input: str) -> uuid.UUID:
    """Resolve role name or uuid string to valid Role UUID in DB"""
    clean_role = role_input.strip().lower()
    if clean_role in ["viewer", "viewers"]:
        target_name = "viewer"
    elif clean_role in ["analyst", "security_analyst", "security analyst"]:
        target_name = "security_analyst"
    elif clean_role in ["admin", "administrator", "org_admin", "organization_admin"]:
        target_name = "admin"
    elif clean_role in ["superadmin", "super_admin"]:
        target_name = "superadmin"
    else:
        target_name = "viewer"

    role_record = db.query(Role).filter(Role.name == target_name).first()
    if not role_record:
        role_record = Role(id=uuid.uuid4(), name=target_name, description=f"{target_name.capitalize()} Role")
        db.add(role_record)
        db.commit()
        db.refresh(role_record)
    return role_record.id

@router.get("/orgs/{org_id}/invitations")
def list_invitations(
    org_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    try:
        oid = uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid organization ID format")

    user_role = (current_user.get("role") or "").lower().replace(" ", "")
    if user_role not in ["superadmin", "super_admin"]:
        user_org_id = get_current_organization(current_user, db)
        if str(user_org_id) != str(org_id):
            raise HTTPException(status_code=403, detail="Not authorized to view this organization's invitations")

    invites = db.query(Invitation).filter(Invitation.org_id == oid).all()
    roles = {r.id: r.name for r in db.query(Role).all()}

    data = []
    for i in invites:
        expires_at_val = i.expires_at
        expires_at_str = expires_at_val.isoformat() if hasattr(expires_at_val, "isoformat") else str(expires_at_val) if expires_at_val else None

        role_display = roles.get(i.role_id, "viewer") if i.role_id else "viewer"

        data.append({
            "id": str(i.id),
            "email": i.email,
            "role": role_display,
            "role_id": role_display,
            "status": i.status,
            "expires_at": expires_at_str,
            "invited_by": str(i.invited_by) if i.invited_by else None
        })

    return {"success": True, "data": data}

@router.post("/orgs/{org_id}/invitations", dependencies=[Depends(require_permission("manage_users"))])
def create_invitation(
    org_id: str,
    request: InviteRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    try:
        oid = uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid organization ID format")

    user_role = (current_user.get("role") or "").lower().replace(" ", "")
    if user_role not in ["superadmin", "super_admin"]:
        user_org_id = get_current_organization(current_user, db)
        if str(user_org_id) != str(org_id):
            raise HTTPException(status_code=403, detail="Not authorized to invite to this organization")
        if not ("admin" in user_role):
            raise HTTPException(status_code=403, detail="Only org admins can send invites")

    org = db.query(Organization).filter(Organization.id == oid).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # 1. Normalize Email
    normalized_email = request.email.strip().lower()

    # 2. Resolve Role to UUID
    role_uuid = _resolve_role_id(db, request.role)

    # 3. Duplicate Prevention
    existing = db.query(Invitation).filter(
        Invitation.org_id == oid,
        Invitation.email == normalized_email,
        Invitation.status.in_(["PENDING", "ACCEPTED", "ACTIVE"])
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="This employee is already on the allowlist or has a pending invitation.")

    # 4. Resolve inviter user id
    current_uid = current_user.get("id") or current_user.get("user_id")
    try:
        inviter_uuid = uuid.UUID(str(current_uid)) if current_uid else None
    except ValueError:
        inviter_uuid = None

    invite = Invitation(
        id=uuid.uuid4(),
        org_id=oid,
        email=normalized_email,
        role_id=role_uuid,
        invited_by=inviter_uuid,
        status="PENDING",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )
    db.add(invite)

    # 5. Optional Audit Log
    try:
        if inviter_uuid:
            audit = AuditLog(
                id=uuid.uuid4(),
                user_id=inviter_uuid,
                organization_id=oid,
                action=AuditAction.USER_CREATED,
                resource_type="Invitation",
                resource_id=invite.id,
                details={"invited_email": normalized_email, "role": request.role}
            )
            db.add(audit)
    except Exception:
        pass

    db.commit()
    db.refresh(invite)

    invite_link = f"https://aegivion.vercel.app/login"

    return {
        "success": True,
        "message": f"Invitation sent to {normalized_email}",
        "invite_link": invite_link
    }

@router.get("/invitations/{token}")
def get_invitation_details(token: str, db: Session = Depends(get_db)):
    invite = db.query(Invitation).filter(Invitation.token == token).first()
    if not invite:
        raise HTTPException(status_code=404, detail="Invalid invitation token")

    if invite.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Invitation is already {invite.status}")

    if invite.expires_at < datetime.now(timezone.utc):
        invite.status = "EXPIRED"
        db.commit()
        raise HTTPException(status_code=400, detail="Invitation has expired")

    org = db.query(Organization).filter(Organization.id == invite.org_id).first()
    role = db.query(Role).filter(Role.id == invite.role_id).first()

    return {
        "success": True,
        "data": {
            "email": invite.email,
            "role": role.name if role else "viewer",
            "organization_name": org.name if org else "Unknown Organization",
            "expires_at": invite.expires_at.isoformat()
        }
    }

@router.delete("/invitations/{id}", dependencies=[Depends(require_permission("manage_users"))])
def revoke_invitation(
    id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    try:
        inv_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid invitation ID format")

    invite = db.query(Invitation).filter(Invitation.id == inv_uuid).first()
    if not invite:
        raise HTTPException(status_code=404, detail="Invitation not found")

    user_role = (current_user.get("role") or "").lower().replace(" ", "")
    if user_role not in ["superadmin", "super_admin"]:
        user_org_id = get_current_organization(current_user, db)
        if str(user_org_id) != str(invite.org_id):
            raise HTTPException(status_code=403, detail="Not authorized")
        if not ("admin" in user_role):
            raise HTTPException(status_code=403, detail="Only org admins can revoke invites")

    invite.status = "REVOKED"
    db.commit()
    return {"success": True, "message": "Invitation revoked"}
