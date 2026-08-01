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
    id_token: str

class LoginResponse(BaseModel):
    success: bool
    token: str
    user: Dict[str, Any]


# ---------------------------------------------------------------------------
# Helper — verify Google id_token
# ---------------------------------------------------------------------------

async def _verify_google_token(id_token: str) -> Dict[str, Any]:
    """
    Verifies a Google id_token using Google's public tokeninfo endpoint.
    Returns the token payload (email, name, sub, etc.) on success.
    Raises HTTPException 401 on failure.
    """
    google_client_id = os.getenv("GOOGLE_CLIENT_ID", "")

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": id_token},
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google token verification failed. Invalid or expired token.",
        )

    payload = response.json()

    # Ensure token was issued for OUR app (prevents token substitution attacks)
    if google_client_id and payload.get("aud") != google_client_id:
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

    # 1. Verify the Google token
    google_payload = await _verify_google_token(request.id_token)

    email: str = google_payload.get("email", "")
    given_name: str = google_payload.get("given_name", "Google")
    family_name: str = google_payload.get("family_name", "User")
    google_sub: str = google_payload.get("sub", "")  # unique Google user ID

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not retrieve email from Google account.",
        )

    # 2. Look up existing user
    user = db.query(User).filter(User.email == email).first()
    org_id = str(uuid.uuid4())
    role_name = "viewer"

    if user:
        # Existing user — fetch their role
        org_id = str(user.organization_id)
        role = db.query(Role).filter(Role.id == user.role_id).first()
        if role:
            role_name = role.name
        first_name = user.first_name
        last_name = user.last_name
        user_id = str(user.id)

        # Update last_login_at if column exists (best-effort)
        try:
            from datetime import datetime
            user.last_login_at = datetime.utcnow()
            db.commit()
        except Exception:
            db.rollback()

    else:
        # 3. New user — provision with viewer role
        viewer_role = db.query(Role).filter(Role.name == "viewer").first()

        if viewer_role:
            # We need an organization — try to find a default org or create one
            from app.models.organization import Organization  # type: ignore
            default_org = db.query(Organization).first()

            if default_org:
                new_org_id = default_org.id
            else:
                # Fallback: just use a UUID (no org required for dev)
                new_org_id = uuid.uuid4()

            new_user = User(
                email=email,
                first_name=given_name,
                last_name=family_name,
                password_hash="GOOGLE_OAUTH_NO_PASSWORD",  # sentinel — cannot log in with password
                status=UserStatus.ACTIVE,
                email_verified=True,
                organization_id=new_org_id,
                role_id=viewer_role.id,
            )
            try:
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                user_id = str(new_user.id)
                org_id = str(new_org_id)
            except Exception as exc:
                db.rollback()
                # If DB insert fails (e.g. org FK constraint), fall back to
                # a stateless JWT so dev flow still works without a seeded DB
                user_id = google_sub or str(uuid.uuid4())
        else:
            # No DB / not seeded — use stateless JWT (dev-only fallback)
            user_id = google_sub or str(uuid.uuid4())

        first_name = given_name
        last_name = family_name
        role_name = "viewer"

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
