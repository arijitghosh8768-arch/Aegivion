from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

from app.database import get_db
from app.models.user import User
from app.models.role import Role
from app.core.security import SecurityService, get_current_user

router = APIRouter()

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    success: bool
    token: str
    user: Dict[str, Any]

@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    # 1. Look for user in DB
    user = db.query(User).filter(User.email == request.email).first()
    
    role_name = "viewer"
    org_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    first_name = "Guest"
    last_name = "User"

    if user:
        # Validate password using User model helper
        if not user.verify_password(request.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password"
            )
        user_id = str(user.id)
        org_id = str(user.organization_id)
        first_name = user.first_name
        last_name = user.last_name
        # Fetch role name
        role = db.query(Role).filter(Role.id == user.role_id).first()
        if role:
            role_name = role.name
    else:
        # Fallback for development if not seeded: allow admin, analyst, viewer with standard password
        if request.password == "Admin123!":
            if request.email == "admin@aegivion.com":
                role_name = "admin"
                first_name = "Admin"
                last_name = "User"
            elif request.email == "analyst@aegivion.com":
                role_name = "analyst"
                first_name = "Security"
                last_name = "Analyst"
            elif request.email == "viewer@aegivion.com":
                role_name = "viewer"
                first_name = "Read-Only"
                last_name = "Viewer"
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

    # 2. Create access token using SecurityService
    token_service = SecurityService()
    token = token_service.create_access_token(user_id=user_id, org_id=org_id, role=role_name)
    
    return LoginResponse(
        success=True,
        token=token,
        user={
            "id": user_id,
            "email": request.email,
            "first_name": first_name,
            "last_name": last_name,
            "name": f"{first_name} {last_name}",
            "role": role_name,
            "organization_id": org_id
        }
    )

@router.post("/logout")
def logout():
    return {"success": True, "message": "Logged out successfully"}

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
