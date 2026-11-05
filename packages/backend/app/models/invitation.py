import secrets
from datetime import datetime, timezone, timedelta
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel

def generate_token():
    return secrets.token_urlsafe(32)

class Invitation(BaseModel):
    __tablename__ = "invitations"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    email = Column(String(255), nullable=False)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True)
    invited_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(50), default="PENDING", nullable=False)
    token = Column(String(255), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    organization = relationship("Organization", back_populates="invitations")
    role = relationship("Role")
    inviter = relationship("User", foreign_keys=[invited_by])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.org_id = kwargs.get("org_id")
        self.email = kwargs.get("email")
        self.role_id = kwargs.get("role_id")
        self.invited_by = kwargs.get("invited_by")
        self.status = kwargs.get("status", "PENDING")
        self.token = kwargs.get("token", generate_token())
        self.expires_at = kwargs.get("expires_at") or (datetime.now(timezone.utc) + timedelta(days=7))
