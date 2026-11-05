from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel

class AuthSession(BaseModel):
    __tablename__ = "sessions"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_token_hash = Column(String(255), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)
    ip_hash_or_safe_metadata = Column(String(255), nullable=True)

    user = relationship("User", back_populates="sessions")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_id = kwargs.get("user_id")
        self.session_token_hash = kwargs.get("session_token_hash")
        self.expires_at = kwargs.get("expires_at")
        self.last_used_at = kwargs.get("last_used_at") or datetime.now(timezone.utc)
        self.revoked_at = kwargs.get("revoked_at")
        self.user_agent = kwargs.get("user_agent")
        self.ip_address = kwargs.get("ip_address")
        self.ip_hash_or_safe_metadata = kwargs.get("ip_hash_or_safe_metadata")

    def is_active(self) -> bool:
        now = datetime.now(timezone.utc)
        if self.revoked_at:
            return False
        if self.expires_at:
            t = self.expires_at
            if isinstance(t, str):
                try:
                    t = datetime.fromisoformat(t)
                except Exception:
                    pass
            if isinstance(t, datetime):
                if t.tzinfo is None:
                    t = t.replace(tzinfo=timezone.utc)
                if now > t:
                    return False
        return True
