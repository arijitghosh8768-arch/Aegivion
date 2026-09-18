
from datetime import datetime
from app.database.base import BaseModel

class Session(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_id = kwargs.get("user_id")
        self.session_token_hash = kwargs.get("session_token_hash")
        self.expires_at = kwargs.get("expires_at")
        self.last_used_at = kwargs.get("last_used_at") or datetime.utcnow()
        self.revoked_at = kwargs.get("revoked_at")
        self.user_agent = kwargs.get("user_agent")
        self.ip_hash_or_safe_metadata = kwargs.get("ip_hash_or_safe_metadata")

    def is_active(self):
        now = datetime.utcnow()
        if self.revoked_at:
            return False
        if self.expires_at:
            t = self.expires_at
            if isinstance(t, str):
                try:
                    t = datetime.fromisoformat(t)
                except Exception:
                    pass
            if isinstance(t, datetime) and now > t:
                return False
        return True

    def dict(self):
        res = super().dict()
        res.update({
            "user_id": str(self.user_id) if self.user_id else None,
            "session_token_hash": self.session_token_hash,
            "expires_at": self.expires_at.isoformat() if isinstance(self.expires_at, datetime) else self.expires_at,
            "last_used_at": self.last_used_at.isoformat() if isinstance(self.last_used_at, datetime) else self.last_used_at,
            "revoked_at": self.revoked_at.isoformat() if isinstance(self.revoked_at, datetime) and self.revoked_at else self.revoked_at,
            "user_agent": self.user_agent,
            "ip_hash_or_safe_metadata": self.ip_hash_or_safe_metadata
        })
        return res

