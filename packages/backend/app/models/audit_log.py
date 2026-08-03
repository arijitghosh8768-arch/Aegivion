import enum
from app.database.base import BaseModel

class AuditAction(str, enum.Enum):
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    FINDING_RESOLVED = "finding_resolved"
    REPORT_GENERATED = "report_generated"
    SETTINGS_UPDATED = "settings_updated"
    INTEGRATION_ADDED = "integration_added"

class AuditLog(BaseModel):
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
        res = super().dict()
        res.update({
            "user_id": str(self.user_id) if self.user_id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": str(self.resource_id) if self.resource_id else None,
            "details": self.details,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent
        })
        return res

