import enum
import uuid
from sqlalchemy import Column, String, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID, ENUM
from sqlalchemy.orm import relationship
from app.database.base import BaseModel

class AuditAction(str, enum.Enum):
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"
    USER_DELETED = "USER_DELETED"
    FINDING_CREATED = "FINDING_CREATED"
    FINDING_UPDATED = "FINDING_UPDATED"
    FINDING_RESOLVED = "FINDING_RESOLVED"
    REPORT_GENERATED = "REPORT_GENERATED"
    SETTINGS_UPDATED = "SETTINGS_UPDATED"
    INTEGRATION_ADDED = "INTEGRATION_ADDED"

class AuditLog(BaseModel):
    __tablename__ = "audit_logs"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    action = Column(ENUM(AuditAction, name="auditaction", create_type=False), nullable=False)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(UUID(as_uuid=True), nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)

    user = relationship("User", foreign_keys=[user_id])
    organization = relationship("Organization", foreign_keys=[organization_id])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_id = kwargs.get("user_id")
        self.organization_id = kwargs.get("organization_id")
        self.action = kwargs.get("action")
        self.resource_type = kwargs.get("resource_type")
        self.resource_id = kwargs.get("resource_id")
        self.details = kwargs.get("details") or {}
        self.ip_address = kwargs.get("ip_address")
        self.user_agent = kwargs.get("user_agent")

    def dict(self):
        res = super().dict() if hasattr(super(), "dict") else {}
        res.update({
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "action": self.action.value if hasattr(self.action, "value") else str(self.action),
            "resource_type": self.resource_type,
            "resource_id": str(self.resource_id) if self.resource_id else None,
            "details": self.details,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent
        })
        return res
