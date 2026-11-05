from datetime import datetime, timezone
import enum
from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel

class OrgRole(str, enum.Enum):
    ORG_ADMIN = "ORG_ADMIN"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    VIEWER = "VIEWER"
    MEMBER = "MEMBER"

class MemberStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"

class OrganizationMember(BaseModel):
    __tablename__ = "organization_members"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(50), nullable=False, default="MEMBER")
    status = Column(String(50), nullable=False, default="ACTIVE")

    user = relationship("User", back_populates="memberships")
    organization = relationship("Organization", back_populates="members")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_id = kwargs.get("user_id")
        self.organization_id = kwargs.get("organization_id")
        self.role = kwargs.get("role") or OrgRole.MEMBER.value
        self.status = kwargs.get("status") or MemberStatus.ACTIVE.value
