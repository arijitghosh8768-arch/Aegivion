import uuid
import secrets
from datetime import datetime, timedelta
from app.database.base import BaseModel

def generate_token():
    return secrets.token_urlsafe(32)

class Invitation(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.org_id = kwargs.get("org_id")
        self.email = kwargs.get("email")
        self.role_id = kwargs.get("role_id")
        self.invited_by = kwargs.get("invited_by")
        self.status = kwargs.get("status", "PENDING")
        self.token = kwargs.get("token", generate_token())
        self.expires_at = kwargs.get("expires_at", datetime.utcnow() + timedelta(days=7))

    def dict(self):
        res = super().dict()
        res.update({
            "org_id": str(self.org_id) if self.org_id else None,
            "email": self.email,
            "role_id": self.role_id,
            "invited_by": str(self.invited_by) if self.invited_by else None,
            "status": self.status,
            "token": self.token,
            "expires_at": self.expires_at.isoformat() if isinstance(self.expires_at, datetime) else self.expires_at
        })
        return res
