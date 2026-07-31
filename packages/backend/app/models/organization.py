from datetime import datetime
import enum
from sqlalchemy import Column, String, DateTime, Enum, ForeignKey, JSON, Integer
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
    subscription_plan = Column(Enum(SubscriptionPlan), default=SubscriptionPlan.FREE)
    owner_id = Column(UUID(as_uuid=True), nullable=True)
    settings = Column(JSON, default={})
    
    # Subscription details
    trial_ends_at = Column(DateTime, nullable=True)
    subscription_ends_at = Column(DateTime, nullable=True)
    max_users = Column(Integer, default=5)
    max_projects = Column(Integer, default=1)
    
    # Features flags
    features = Column(JSON, default={
        "advanced_security": False,
        "ai_assistant": False,
        "custom_reports": False,
        "api_access": False
    })
    
    # Relationships
    users = relationship("User", back_populates="organization", foreign_keys="[User.organization_id]")
    roles = relationship("Role", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")
    
    def is_trial_active(self) -> bool:
        if not self.trial_ends_at:
            return False
        return datetime.utcnow() < self.trial_ends_at
    
    def can_add_user(self) -> bool:
        return len(self.users) < self.max_users
