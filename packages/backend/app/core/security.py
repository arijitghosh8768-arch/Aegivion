import jwt
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt

class SecurityService:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SecurityService, cls).__new__(cls)
            cls._instance.security = HTTPBearer(auto_error=False)
            cls._instance.private_key = cls._instance._load_or_generate_private_key()
            cls._instance.public_key = cls._instance.private_key.public_key()
        return cls._instance

    def _load_or_generate_private_key(self):
        # Dynamically generate a 2048-bit RSA key pair for development
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    def create_access_token(self, user_id: str, org_id: str, role: str) -> str:
        """Create JWT access token with short expiry using RS256"""
        now = datetime.utcnow()
        payload = {
            "sub": str(user_id),
            "org": str(org_id),
            "role": role,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=15)).timestamp()),
            "jti": str(uuid.uuid4()),
            "type": "access"
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")
    
    def create_refresh_token(self, user_id: str, device_id: str) -> str:
        """Create refresh token with longer expiry using RS256"""
        now = datetime.utcnow()
        payload = {
            "sub": str(user_id),
            "device": device_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=7)).timestamp()),
            "jti": str(uuid.uuid4()),
            "type": "refresh"
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")
    
    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """Verify JWT token with proper validation"""
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256"],
                options={"require": ["exp", "iat", "sub", "type"]}
            )
            
            # Validate token type
            if payload.get("type") != token_type:
                raise HTTPException(401, "Invalid token type")
                
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "Token has expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(401, f"Invalid token: {str(e)}")
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt with proper salt rounds"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# FastAPI Dependency for protected routes
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(SecurityService().security)
) -> Dict[str, Any]:
    if not credentials:
        raise HTTPException(401, "Authentication credentials missing")
    token = credentials.credentials
    payload = SecurityService().verify_token(token)
    return {
        "user_id": payload["sub"],
        "organization_id": payload["org"],
        "role": payload["role"]
    }
