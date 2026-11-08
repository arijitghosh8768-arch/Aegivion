from datetime import datetime, timezone
import uuid
import enum
from typing import Dict, Any, List, Optional
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
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
    PENDING_APPROVAL = "pending_approval"

class FindingSource(str, enum.Enum):
    CSPM = "cspm"
    IAM = "iam"
    NETWORK = "network"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    DATA = "data"

class Finding(BaseModel):
    __tablename__ = "findings"

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(String(2000), nullable=False)
    severity = Column(String(50), default="medium", nullable=False, index=True)
    status = Column(String(50), default="open", nullable=False, index=True)
    source = Column(String(50), default="cspm", nullable=False)
    resource_id = Column(String(200), nullable=False, index=True)
    resource_name = Column(String(300), nullable=False)
    resource_type = Column(String(100), nullable=False)
    resource_region = Column(String(100), nullable=True)
    cloud_provider = Column(String(50), nullable=False)
    rule_id = Column(String(100), nullable=False)
    rule_name = Column(String(300), nullable=False)
    risk_score = Column(Float, nullable=True)
    cvss_score = Column(Float, nullable=True)
    remediation_steps = Column(JSONB, default=dict)
    evidence = Column(JSONB, default=dict)
    evidence_source = Column(String(100), default="aws_api")
    evidence_collected_at = Column(DateTime(timezone=True), nullable=True)
    evidence_confidence = Column(String(50), default="HIGH")
    evidence_quality_score = Column(Float, default=90.0)
    tags = Column(JSONB, default=list)
    assigned_to_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_to = Column(String(200), nullable=True)
    notes = Column(JSONB, default=list)
    timeline = Column(JSONB, default=list)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    fingerprint = Column(String(128), nullable=True, index=True)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    occurrence_count = Column(Integer, default=1)
    reopened_at = Column(DateTime(timezone=True), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.title = kwargs.get("title")
        self.description = kwargs.get("description") or ""
        self.severity = (kwargs.get("severity") or "medium").lower()
        self.status = (kwargs.get("status") or "open").lower()
        self.source = (kwargs.get("source") or "cspm").lower()
        self.resource_id = kwargs.get("resource_id")
        self.resource_name = kwargs.get("resource_name") or kwargs.get("resource_id") or "unknown"
        self.resource_type = kwargs.get("resource_type") or "unknown"
        self.resource_region = kwargs.get("resource_region") or "global"
        self.cloud_provider = (kwargs.get("cloud_provider") or "AWS").upper()
        self.rule_id = kwargs.get("rule_id")
        self.rule_name = kwargs.get("rule_name") or kwargs.get("rule_id") or "Security Rule"
        self.risk_score = kwargs.get("risk_score")
        self.cvss_score = kwargs.get("cvss_score")
        self.remediation_steps = kwargs.get("remediation_steps") or {}
        self.evidence = kwargs.get("evidence") or {}
        self.evidence_source = kwargs.get("evidence_source") or "aws_api"
        self.evidence_collected_at = kwargs.get("evidence_collected_at") or datetime.now(timezone.utc)
        self.evidence_confidence = kwargs.get("evidence_confidence") or "HIGH"
        self.evidence_quality_score = kwargs.get("evidence_quality_score") or 90.0
        self.tags = kwargs.get("tags") or []
        self.assigned_to_id = kwargs.get("assigned_to_id")
        self.assigned_to = kwargs.get("assigned_to")
        self.notes = kwargs.get("notes") or []
        self.timeline = kwargs.get("timeline") or []
        self.resolved_at = kwargs.get("resolved_at")
        self.resolved_by_id = kwargs.get("resolved_by_id")
        self.fingerprint = kwargs.get("fingerprint")
        self.first_seen = kwargs.get("first_seen") or datetime.now(timezone.utc)
        self.last_seen = kwargs.get("last_seen") or datetime.now(timezone.utc)
        self.occurrence_count = kwargs.get("occurrence_count") or 1
        self.reopened_at = kwargs.get("reopened_at")

    def dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id) if self.id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "source": self.source,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "resource_region": self.resource_region,
            "cloud_provider": self.cloud_provider,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "risk_score": self.risk_score,
            "cvss_score": self.cvss_score,
            "remediation_steps": self.remediation_steps,
            "evidence": self.evidence,
            "evidence_source": self.evidence_source,
            "evidence_collected_at": self.evidence_collected_at.isoformat() if isinstance(self.evidence_collected_at, datetime) else self.evidence_collected_at,
            "evidence_confidence": self.evidence_confidence,
            "evidence_quality_score": self.evidence_quality_score,
            "tags": self.tags,
            "assigned_to_id": str(self.assigned_to_id) if self.assigned_to_id else None,
            "assigned_to": self.assigned_to,
            "notes": self.notes,
            "timeline": self.timeline,
            "resolved_at": self.resolved_at.isoformat() if isinstance(self.resolved_at, datetime) else self.resolved_at,
            "resolved_by_id": str(self.resolved_by_id) if self.resolved_by_id else None,
            "fingerprint": self.fingerprint,
            "first_seen": self.first_seen.isoformat() if isinstance(self.first_seen, datetime) else self.first_seen,
            "last_seen": self.last_seen.isoformat() if isinstance(self.last_seen, datetime) else self.last_seen,
            "occurrence_count": self.occurrence_count,
            "reopened_at": self.reopened_at.isoformat() if isinstance(self.reopened_at, datetime) else self.reopened_at,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "updated_at": self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else self.updated_at
        }

