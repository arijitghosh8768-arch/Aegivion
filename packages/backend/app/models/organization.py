from datetime import datetime, timezone
import enum
from sqlalchemy import Column, String, DateTime, Enum, JSON, Integer
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel

class SubscriptionPlan(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"

class Organization(BaseModel):
    __tablename__ = "organizations"

    name = Column(String(200), nullable=False)
    slug = Column(String(200), unique=True, nullable=False, index=True)
    industry = Column(String(100), nullable=True)
    subscription_plan = Column(String(50), default="free")
    owner_id = Column(UUID(as_uuid=True), nullable=True)
    settings = Column(JSON, default=dict)

    # Subscription details
    trial_ends_at = Column(DateTime(timezone=True), nullable=True)
    subscription_ends_at = Column(DateTime(timezone=True), nullable=True)
    max_users = Column(Integer, default=5)
    max_projects = Column(Integer, default=1)

    # Feature flags
    features = Column(JSON, default=lambda: {
        "advanced_security": False,
        "ai_assistant": False,
        "custom_reports": False,
        "api_access": False
    })
    security_policy = Column(JSON, default=lambda: {"require_exception_approval": False})

    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan", foreign_keys="[User.organization_id]")
    roles = relationship("Role", back_populates="organization", cascade="all, delete-orphan")
    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    invitations = relationship("Invitation", back_populates="organization", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = kwargs.get("name")
        self.slug = kwargs.get("slug")
        self.industry = kwargs.get("industry")
        self.subscription_plan = kwargs.get("subscription_plan") or SubscriptionPlan.FREE
        self.owner_id = kwargs.get("owner_id")
        self.settings = kwargs.get("settings") or {}
        self.trial_ends_at = kwargs.get("trial_ends_at")
        self.subscription_ends_at = kwargs.get("subscription_ends_at")
        self.max_users = kwargs.get("max_users") or 5
        self.max_projects = kwargs.get("max_projects") or 1
        self.features = kwargs.get("features") or {
            "advanced_security": False,
            "ai_assistant": False,
            "custom_reports": False,
            "api_access": False
        }
        self.security_policy = kwargs.get("security_policy") or {"require_exception_approval": False}

    def is_trial_active(self) -> bool:
        if not self.trial_ends_at:
            return False
        t = self.trial_ends_at
        if isinstance(t, str):
            try:
                t = datetime.fromisoformat(t)
            except Exception:
                return False
        now = datetime.now(timezone.utc)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return now < t

    def can_add_user(self) -> bool:
        user_list = getattr(self, "users", []) or []
        return len(user_list) < self.max_users
