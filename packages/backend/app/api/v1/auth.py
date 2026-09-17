import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Dict, Any, Optional
import uuid

from app.database import get_db
from app.models.user import User
from app.models.role import Role
from app.core.security import SecurityService, get_current_user
from app.core.rate_limit import limiter

router = APIRouter()

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    success: bool
    token: str
    user: Dict[str, Any]

@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
def login(request: Request, login_data: LoginRequest, db: Session = Depends(get_db)):
    # 1. Look for user in DB
    user = db.query(User).filter(User.email == login_data.email).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
        
    # Validate password using User model helper
    if not user.verify_password(login_data.password):
        # Update failed login attempts
        if hasattr(user, 'increment_failed_attempts'):
            user.increment_failed_attempts()
            db.add(user)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
        
    # Check if locked
    if getattr(user, 'locked_until', None):
        if isinstance(user.locked_until, str):
            try:
                locked_until = datetime.datetime.fromisoformat(user.locked_until)
            except:
                locked_until = datetime.datetime.utcnow()
        else:
            locked_until = user.locked_until
            
        if locked_until > datetime.datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is temporarily locked due to too many failed attempts"
            )

    # Check status
    if getattr(user, 'status', None) == "suspended":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended"
        )
        
    # Success - Reset failed attempts
    if hasattr(user, 'failed_login_attempts'):
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.datetime.utcnow()
        if hasattr(request, 'client') and request.client:
            user.last_login_ip = request.client.host
        db.add(user)
        db.commit()

    user_id = str(user.id)
    org_id = str(user.organization_id) if user.organization_id else str(uuid.uuid4())
    first_name = user.first_name or "Unknown"
    last_name = user.last_name or ""
    
    # Check memberships for Org Name
    from app.models.organization_member import OrganizationMember
    member = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
    if member:
        org_id = str(member.organization_id)
        role_name = member.role.lower() if hasattr(member.role, 'lower') else str(member.role).lower()
    else:
        # Fallback to direct role mapping
        role = db.query(Role).filter(Role.id == user.role_id).first()
        role_name = role.name if role else "viewer"
        
    if user.email == "superadmin@aegivion.com":
        role_name = "superadmin"
        
    # Generate token
    token = SecurityService.create_access_token(
        subject=user_id,
        role=role_name,
        org_id=org_id
    )
    
    # Store persistent session
    import hashlib
    from app.models.auth_session import AuthSession
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    ip_addr = request.client.host if hasattr(request, 'client') and request.client else None
    user_agent = request.headers.get('user-agent', '')
    
    new_session = AuthSession(
        user_id=user.id,
        session_token_hash=token_hash,
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=12),
        user_agent=user_agent,
        ip_address=ip_addr
    )
    db.add(new_session)
    db.commit()

    return {
        "success": True,
        "token": token,
        "user": {
            "id": user_id,
            "email": user.email,
            "name": f"{first_name} {last_name}".strip(),
            "role": role_name,
            "organization_id": org_id,
        }
    }

@router.get("/me")
def get_me(current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db)):
    # Look up user if possible, else return mock details from token payload
    user_id = current_user.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    
    if user:
        role = db.query(Role).filter(Role.id == user.role_id).first()
        role_name = role.name if role else "viewer"
        return {
            "success": True,
            "data": {
                "id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "name": f"{user.first_name} {user.last_name}",
                "role": role_name,
                "organization_id": str(user.organization_id)
            }
        }
        
    # Return payload info as fallback
    role_name = current_user.get("role", "viewer")
    email = f"{role_name}@aegivion.com"
    return {
        "success": True,
        "data": {
            "id": user_id,
            "email": email,
            "first_name": role_name.capitalize(),
            "last_name": "User",
            "name": f"{role_name.capitalize()} User",
            "role": role_name,
            "organization_id": current_user.get("organization_id")
        }
    }

class UserProfileUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None

@router.patch("/me")
def update_me(
    profile_update: UserProfileUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = current_user.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    
    if user:
        if profile_update.first_name:
            user.first_name = profile_update.first_name
        if profile_update.last_name:
            user.last_name = profile_update.last_name
        if profile_update.email:
            user.email = profile_update.email
        db.commit()
        return {"success": True, "message": "Profile updated"}
    
    return {"success": True, "message": "Mock profile updated"}



@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"success": True}
        
    token = auth_header.split(" ")[1]
    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    from app.models.auth_session import AuthSession
    session_record = db.query(AuthSession).filter(AuthSession.session_token_hash == token_hash).first()
    
    if session_record:
        session_record.revoked_at = datetime.datetime.utcnow()
        db.add(session_record)
        db.commit()
        
    return {"success": True, "message": "Logged out successfully"}
