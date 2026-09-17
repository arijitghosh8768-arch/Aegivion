
from datetime import datetime
import enum
from app.database.base import BaseModel
import uuid

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
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "id" not in kwargs or not kwargs["id"]:
            self.id = uuid.uuid4()
        self.user_id = kwargs.get("user_id")
        self.organization_id = kwargs.get("organization_id")
        self.role = kwargs.get("role") or OrgRole.MEMBER
        self.status = kwargs.get("status") or MemberStatus.ACTIVE
        self.created_at = kwargs.get("created_at") or datetime.utcnow()
        self.updated_at = kwargs.get("updated_at") or datetime.utcnow()

    def dict(self):
        res = super().dict()
        res.update({
            "user_id": str(self.user_id) if self.user_id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "role": self.role,
            "status": self.status,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "updated_at": self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else self.updated_at
        })
        return res

