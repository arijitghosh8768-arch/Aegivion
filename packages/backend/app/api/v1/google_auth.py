"""
Google OAuth endpoint — POST /v1/auth/google

Flow:
  1. Frontend sends the id_token returned by Google Identity Services
  2. We verify it against Google's tokeninfo endpoint (no extra deps needed)
     OR use google-auth library if installed
  3. Extract email / name / google_sub from the verified payload
  4. Upsert user in DB (create if not exists, defaulting to 'viewer' role)
  5. Return same LoginResponse shape as the password-based login endpoint
"""

import os
import uuid
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any

from app.database import get_db
from app.models.user import User, UserStatus
from app.models.role import Role
from app.core.security import SecurityService

router = APIRouter()

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

class GoogleLoginRequest(BaseModel):
    id_token: str = None
    access_token: str = None

class LoginResponse(BaseModel):
    success: bool
    token: str
    user: Dict[str, Any]


# ---------------------------------------------------------------------------
# Helper — verify Google id_token
# ---------------------------------------------------------------------------

async def _verify_google_token(token: str, is_access_token: bool = False) -> Dict[str, Any]:
    """
    Verifies a Google token. For access_tokens, it hits the userinfo endpoint to get full profile data (name, etc).
    For id_tokens, it hits tokeninfo.
    Returns the token payload (email, name, sub, etc.) on success.
    Raises HTTPException 401 on failure.
    """
    google_client_id = os.getenv("GOOGLE_CLIENT_ID", "84307924515-g3rteqggcrl485f84i2fh04nl0ki8k9m.apps.googleusercontent.com")

    async with httpx.AsyncClient(timeout=10) as client:
        if is_access_token:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {token}"}
            )
        else:
            response = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": token},
            )

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google token verification failed. Invalid or expired token.",
        )

    payload = response.json()

    # Ensure token was issued for OUR app (prevents token substitution attacks)
    if not is_access_token and google_client_id and payload.get("aud") != google_client_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google token audience mismatch.",
        )

    if not payload.get("email_verified", False) and payload.get("email_verified") != "true":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google account email is not verified.",
        )

    return payload


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/google", response_model=LoginResponse)
async def google_login(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate via Google OAuth id_token.
    Creates the user on first login (viewer role), then returns an Aegivion JWT.
    """

    if not request.id_token and not request.access_token:
        raise HTTPException(400, "Missing id_token or access_token")
        
    # 1. Verify the Google token
    token = request.access_token or request.id_token
    is_access = bool(request.access_token)
    google_payload = await _verify_google_token(token, is_access)

    email: str = google_payload.get("email", "")
    given_name: str = google_payload.get("given_name", "Google")
    family_name: str = google_payload.get("family_name", "User")
    google_sub: str = google_payload.get("sub", "")  # unique Google user ID

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not retrieve email from Google account.",
        )

    # 2. Look up existing user by email or sub
    user = db.query(User).filter(User.email == email).first()
    if not user and google_sub:
        all_users = db.query(User).all()
        user = next((u for u in all_users if getattr(u, 'google_sub', None) == google_sub), None)
        
    org_id = str(uuid.uuid4())
    role_name = "viewer"

    if user:
        # Existing user — fetch their role
        org_id = str(user.organization_id)
        role = db.query(Role).filter(Role.id == user.role_id).first() if user.role_id else None
        if not role:
            # check string role
            all_roles = db.query(Role).all()
            role = next((r for r in all_roles if str(r.id) == str(user.role_id) or r.name.lower() == str(user.role_id).lower()), None)
            
        if role:
            role_name = role.name
        
        # Fix missing names from earlier bug
        if (user.first_name == "Google" and user.last_name == "User") and (given_name != "Google"):
            user.first_name = given_name
            user.last_name = family_name

        first_name = user.first_name
        last_name = user.last_name
        user_id = str(user.id)

        # Update last_login_at
        try:
            from datetime import datetime
            user.last_login_at = datetime.utcnow()
            # In case this user was made a superadmin manually
            if getattr(user, 'is_platform_admin', False):
                role_name = "superadmin"
            db.commit()
        except Exception:
            db.rollback()

    else:
        # 3. Check for Invitation
        from app.models.invitation import Invitation
        from datetime import datetime
        all_invites = db.query(Invitation).all()
        invite = next((i for i in all_invites if i.email.lower() == email.lower() and i.status == "PENDING" and (isinstance(i.expires_at, datetime) and i.expires_at > datetime.utcnow() or isinstance(i.expires_at, str) and datetime.fromisoformat(i.expires_at) > datetime.utcnow())), None)
        
        if not invite:
            # Create user without org (Onboarding flow)
            new_org_id = None
            role_id = "platform_user"
            is_invite_flow = False
        else:
            new_org_id = invite.org_id
            role_id = invite.role_id
            is_invite_flow = True
            
        new_user = User(
            email=email,
            first_name=given_name,
            last_name=family_name,
            password_hash="GOOGLE_OAUTH_NO_PASSWORD",
            status=UserStatus.ACTIVE,
            email_verified=True,
            organization_id=new_org_id,
            role_id=role_id,
            google_sub=google_sub
        )
        try:
            db.add(new_user)
            
            if is_invite_flow:
                invite.status = "ACCEPTED"
                
                from app.models.audit_log import AuditLog
                audit = AuditLog(
                    action="invitation_accepted",
                    resource_type="User",
                    resource_id=new_user.id,
                    user_id=new_user.id,
                    organization_id=new_org_id,
                    details={}
                )
                db.add(audit)
                
            db.commit()
            
            user_id = str(new_user.id)
            org_id = str(new_org_id)
            role_name = role_id if isinstance(role_id, str) else "viewer"
        except Exception as exc:
            db.rollback()
            raise HTTPException(500, f"Error provisioning user: {str(exc)}")

        first_name = given_name
        last_name = family_name

    # 4. Issue Aegivion JWT (same as password login)
    token_service = SecurityService()
    token = token_service.create_access_token(
        user_id=user_id,
        org_id=org_id,
        role=role_name,
    )

    return LoginResponse(
        success=True,
        token=token,
        user={
            "id": user_id,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "name": f"{first_name} {last_name}",
            "role": role_name,
            "organization_id": org_id,
        },
    )
