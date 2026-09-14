import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base

class OrgSettings(Base):
    __tablename__ = "org_settings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), unique=True, nullable=False)
    
    enabled_cloud_providers = Column(JSON, default=lambda: ["aws"])
    security_policy = Column(JSON, default=lambda: {"require_exception_approval": False, "auto_suppress_non_prod": False})
    notification_preferences = Column(JSON, default=lambda: {"email": True, "slack": False, "severity_threshold": "high"})
    ai_features_enabled = Column(Boolean, default=True)
    branding = Column(JSON, default=lambda: {"company_name": "", "logo_url": "", "theme_color": ""})
    custom_compliance_frameworks = Column(JSON, default=lambda: ["CIS", "SOC2"])
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(36), nullable=True)

    organization = relationship("Organization", backref="settings")
