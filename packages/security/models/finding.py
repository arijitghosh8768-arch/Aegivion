import enum
from sqlalchemy import Column, String, Integer, DateTime, Enum, JSON, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel

class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"

class FindingSource(str, enum.Enum):
    CSPM = "cspm"
    IAM = "iam"
    NETWORK = "network"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    DATA = "data"

class Finding(BaseModel):
    __tablename__ = "findings"
    
    title = Column(String(300), nullable=False)
    description = Column(String(2000), nullable=False)
    severity = Column(Enum(FindingSeverity), nullable=False, index=True)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN, index=True)
    source = Column(Enum(FindingSource), nullable=False)
    
    # Resource details
    resource_id = Column(String(200), nullable=False, index=True)
    resource_name = Column(String(300), nullable=False)
    resource_type = Column(String(100), nullable=False)
    resource_region = Column(String(100), nullable=True)
    cloud_provider = Column(String(50), nullable=False)
    
    # Rule details
    rule_id = Column(String(100), nullable=False)
    rule_name = Column(String(300), nullable=False)
    
    # Risk scoring
    risk_score = Column(Float, nullable=True)
    cvss_score = Column(Float, nullable=True)
    
    # Metadata
    remediation_steps = Column(JSON, nullable=True)
    evidence = Column(JSON, nullable=True)
    tags = Column(JSON, default=[])
    
    # Lifecycle
    assigned_to_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    # Relationships
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])
    resolved_by = relationship("User", foreign_keys=[resolved_by_id])
    
    def calculate_risk_score(self) -> float:
        severity_scores = {
            FindingSeverity.CRITICAL: 10.0,
            FindingSeverity.HIGH: 7.5,
            FindingSeverity.MEDIUM: 5.0,
            FindingSeverity.LOW: 2.5,
            FindingSeverity.INFO: 1.0
        }
        base_score = severity_scores.get(self.severity, 5.0)
        return base_score
