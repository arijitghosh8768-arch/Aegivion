from datetime import datetime, timezone
import uuid
import enum
from typing import Dict, Any, List, Optional
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.database.base import BaseModel

class ComplianceStatus(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"

class ComplianceControlResult(BaseModel):
    __tablename__ = "compliance_results"

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    cloud_account_id = Column(UUID(as_uuid=True), ForeignKey("cloud_accounts_v2.id", ondelete="SET NULL"), nullable=True)
    control_code = Column(String(100), nullable=False, index=True)
    framework_id = Column(String(100), default="CIS_AWS_v3", server_default="CIS_AWS_v3", nullable=False, index=True)
    title = Column(String(300), nullable=True)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=True)
    severity = Column(String(50), default="high", server_default="high", nullable=True)
    status = Column(String(50), default="NOT_ASSESSED", server_default="NOT_ASSESSED", nullable=False, index=True)
    affected_resources = Column(JSONB, default=list, server_default="[]", nullable=True)
    evidence_refs = Column(JSONB, default=list, server_default="[]", nullable=True)
    finding_refs = Column(JSONB, default=list, server_default="[]", nullable=True)
    assessed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=True)
    scan_id = Column(String(100), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.control_code = kwargs.get("control_code")
        self.framework_id = kwargs.get("framework_id") or "CIS_AWS_v3"
        self.title = kwargs.get("title")
        self.description = kwargs.get("description")
        self.category = kwargs.get("category")
        self.severity = kwargs.get("severity") or "high"
        
        status_val = kwargs.get("status") or ComplianceStatus.NOT_ASSESSED
        self.status = status_val.value if hasattr(status_val, 'value') else str(status_val).upper()
        
        self.affected_resources = kwargs.get("affected_resources") or []
        self.evidence_refs = kwargs.get("evidence_refs") or []
        self.finding_refs = kwargs.get("finding_refs") or []
        self.assessed_at = kwargs.get("assessed_at") or datetime.now(timezone.utc)
        self.scan_id = kwargs.get("scan_id")

    def dict(self) -> Dict[str, Any]:
        res = super().dict() if hasattr(super(), "dict") else {}
        status_str = self.status.value if hasattr(self.status, 'value') else str(self.status)
        assessed_str = self.assessed_at.isoformat() if isinstance(self.assessed_at, datetime) else self.assessed_at
        res.update({
            "id": str(self.id) if self.id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "control_code": self.control_code,
            "framework_id": self.framework_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "status": status_str,
            "affected_resources": self.affected_resources,
            "evidence_refs": self.evidence_refs,
            "finding_refs": self.finding_refs,
            "assessed_at": assessed_str,
            "scan_id": self.scan_id
        })
        return res
