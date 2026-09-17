
from datetime import datetime
from app.database.base import BaseModel
import uuid

class AuthSession(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "id" not in kwargs or not kwargs["id"]:
            self.id = uuid.uuid4()
        self.user_id = kwargs.get("user_id")
        self.session_token_hash = kwargs.get("session_token_hash")
        self.created_at = kwargs.get("created_at") or datetime.utcnow()
        self.expires_at = kwargs.get("expires_at")
        self.last_used_at = kwargs.get("last_used_at") or datetime.utcnow()
        self.revoked_at = kwargs.get("revoked_at")
        self.user_agent = kwargs.get("user_agent")
        self.ip_address = kwargs.get("ip_address")

    def dict(self):
        res = super().dict()
        res.update({
            "user_id": str(self.user_id) if self.user_id else None,
            "session_token_hash": self.session_token_hash,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "expires_at": self.expires_at.isoformat() if isinstance(self.expires_at, datetime) else self.expires_at,
            "last_used_at": self.last_used_at.isoformat() if isinstance(self.last_used_at, datetime) else self.last_used_at,
            "revoked_at": self.revoked_at.isoformat() if isinstance(self.revoked_at, datetime) else self.revoked_at,
            "user_agent": self.user_agent,
            "ip_address": self.ip_address
        })
        return res

