from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from pydantic import BaseModel, EmailStr
from datetime import datetime

from app.database import get_db
from app.models.invitation import Invitation
from app.models.organization import Organization
from app.models.audit_log import AuditLog
from app.core.security import get_current_user
from app.api.deps import require_permission
from app.core.tenant import get_current_organization
from app.repositories import OrganizationRepository, InvitationRepository

router = APIRouter()

class InviteRequest(BaseModel):
    email: EmailStr
    role: str

@router.get("/orgs/{org_id}/invitations")
def list_invitations(
    org_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_org_id = get_current_organization(current_user, db)
    user_role = current_user.get("role") if isinstance(current_user, dict) else getattr(current_user, "role", None)
    
    if str(user_org_id) != str(org_id) and user_role not in ["superadmin", "super admin"]:
        raise HTTPException(status_code=403, detail="Not authorized to view this organization's invitations")
        
    invitation_repo = InvitationRepository(db)
    invites = invitation_repo.get_by_organization(org_id)
    
    return {
        "success": True,
        "data": [{
            "id": str(i.id),
            "email": i.email,
            "role_id": i.role_id,
            "status": i.status,
            "expires_at": i.expires_at.isoformat() if hasattr(i.expires_at, "isoformat") else i.expires_at,
            "invited_by": i.invited_by
        } for i in invites]
    }

@router.post("/orgs/{org_id}/invitations")
def create_invitation(
    org_id: str,
    request: InviteRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_org_id = get_current_organization(current_user, db)
    user_role = current_user.get("role") if isinstance(current_user, dict) else getattr(current_user, "role", None)
    
    if str(user_org_id) != str(org_id) and user_role not in ["superadmin", "super admin"]:
        raise HTTPException(status_code=403, detail="Not authorized to invite to this organization")
    if not (user_role and ("admin" in user_role.lower() or "super" in user_role.lower())):
        raise HTTPException(status_code=403, detail="Only org admins can send invites")
        
    org_repo = OrganizationRepository(db)
    org = org_repo.get_organization_by_id(org_id)
    
    # 1. Normalize Email
    normalized_email = request.email.strip().lower()
    
    # 2. Validate Role
    allowed_roles = ["VIEWER", "ANALYST", "SECURITY_ANALYST", "ADMIN", "ORG_ADMIN", "SECURITY_ADMIN", "MEMBER"]
    normalized_role = request.role.upper().replace(" ", "_")
    if normalized_role not in allowed_roles:
        raise HTTPException(status_code=400, detail="Invalid role specified")
        
    # 3. Duplicate Prevention
    invitation_repo = InvitationRepository(db)
    existing = invitation_repo.get_by_organization(org_id)
    for inv in existing:
        if inv.email.strip().lower() == normalized_email and inv.status in ["PENDING", "ACCEPTED", "ACTIVE"]:
            raise HTTPException(status_code=400, detail="This employee is already on the allowlist or has a pending invitation.")

    invite = Invitation(
        org_id=org_id,
        email=normalized_email,
        role_id=normalized_role,
        invited_by=str(current_user.get("id")) if isinstance(current_user, dict) else getattr(current_user, "id"),
        status="PENDING"
    )
    db.add(invite)
    
    audit = AuditLog(
        action="invite_sent",
        resource_type="Invitation",
        resource_id=invite.id,
        user_id=str(current_user.get("id", "system")),
        organization_id=org_id,
        details={"invited_email": request.email, "role": request.role}
    )
    db.add(audit)
    
    db.commit()
    db.refresh(invite)
    
    # In a real system, send email here
    invite_link = f"https://aegivion.onrender.com/accept-invite?token={invite.token}"
    
    return {
        "success": True,
        "message": f"Invitation sent to {request.email}",
        "invite_link": invite_link # for development/debugging
    }

@router.get("/invitations/{token}")
def get_invitation_details(token: str, db: Session = Depends(get_db)):
    invitation_repo = InvitationRepository(db)
    invite = invitation_repo.get_by_token(token)
    if not invite:
        raise HTTPException(status_code=404, detail="Invalid invitation token")
        
    if invite.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Invitation is already {invite.status}")
        
    if invite.expires_at < datetime.utcnow():
        invite.status = "EXPIRED"
        db.commit()
        raise HTTPException(status_code=400, detail="Invitation has expired")
        
    org_repo = OrganizationRepository(db)
    org = org_repo.get_organization_by_id(invite.org_id)
    
    return {
        "success": True,
        "data": {
            "email": invite.email,
            "role": invite.role_id,
            "organization_name": org.name if org else "Unknown Organization",
            "expires_at": invite.expires_at.isoformat()
        }
    }

@router.delete("/invitations/{id}")
def revoke_invitation(
    id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    invitation_repo = InvitationRepository(db)
    invite = invitation_repo.get_by_id(id)
    if not invite:
        raise HTTPException(status_code=404, detail="Invitation not found")
        
    user_org_id = get_current_organization(current_user, db)
    user_role = current_user.get("role") if isinstance(current_user, dict) else getattr(current_user, "role", None)
    
    if str(user_org_id) != str(invite.org_id) and user_role not in ["superadmin", "super admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    if not (user_role and ("admin" in user_role.lower() or "super" in user_role.lower())):
        raise HTTPException(status_code=403, detail="Only org admins can revoke invites")
        
    if invite.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Cannot revoke an invite that is {invite.status}")
        
    invite.status = "REVOKED"
    
    audit = AuditLog(
        action="invite_revoked",
        resource_type="Invitation",
        resource_id=invite.id,
        user_id=str(current_user.get("id", "system")),
        organization_id=invite.org_id,
        details={"invited_email": invite.email}
    )
    db.add(audit)
    
    db.commit()
    return {"success": True, "message": "Invitation revoked"}
