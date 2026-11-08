from datetime import datetime, timezone
import uuid
import enum
from typing import Dict, Any, List, Optional
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.database.base import BaseModel

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    CLOSED = "closed"

class Incident(BaseModel):
    __tablename__ = "incidents"

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    cloud_account_id = Column(UUID(as_uuid=True), ForeignKey("cloud_accounts_v2.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), default="medium", server_default="medium", nullable=False)
    risk_score = Column(Integer, default=50, server_default="50", nullable=True)
    confidence = Column(Float, default=0.80, server_default="0.80", nullable=True)
    status = Column(String(50), default="open", server_default="open", nullable=False, index=True)
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=True)
    finding_ids = Column(JSONB, default=list, server_default="[]", nullable=True)
    asset_ids = Column(JSONB, default=list, server_default="[]", nullable=True)
    evidence = Column(JSONB, default=dict, server_default="{}", nullable=True)
    correlation_fingerprint = Column(String(255), nullable=True, index=True)
    timeline = Column(JSONB, default=list, server_default="[]", nullable=True)
    notes = Column(JSONB, default=list, server_default="[]", nullable=True)
    assigned_to = Column(String(200), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.title = kwargs.get("title") or "Correlated Security Incident"
        self.description = kwargs.get("description") or "Security incident compiled from multiple correlated finding indicators."
        
        status_val = kwargs.get("status") or IncidentStatus.OPEN
        self.status = status_val.value if hasattr(status_val, 'value') else str(status_val).lower()
        
        severity_val = kwargs.get("severity") or "medium"
        self.severity = str(severity_val).lower()
        
        self.risk_score = int(kwargs.get("risk_score") if kwargs.get("risk_score") is not None else 50)
        self.confidence = float(kwargs.get("confidence") if kwargs.get("confidence") is not None else 0.80)
        
        now = datetime.now(timezone.utc)
        self.first_seen_at = kwargs.get("first_seen_at") or now
        self.last_seen_at = kwargs.get("last_seen_at") or now
        self.finding_ids = kwargs.get("finding_ids") or []
        self.asset_ids = kwargs.get("asset_ids") or []
        self.evidence = kwargs.get("evidence") or {}
        self.correlation_fingerprint = kwargs.get("correlation_fingerprint")
        self.timeline = kwargs.get("timeline") or []
        self.notes = kwargs.get("notes") or []
        self.assigned_to = kwargs.get("assigned_to")

    def dict(self) -> Dict[str, Any]:
        res = super().dict() if hasattr(super(), "dict") else {}
        status_str = self.status.value if hasattr(self.status, 'value') else str(self.status)
        first_seen_str = self.first_seen_at.isoformat() if isinstance(self.first_seen_at, datetime) else self.first_seen_at
        last_seen_str = self.last_seen_at.isoformat() if isinstance(self.last_seen_at, datetime) else self.last_seen_at
        res.update({
            "id": str(self.id) if self.id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "status": status_str,
            "first_seen_at": first_seen_str,
            "last_seen_at": last_seen_str,
            "finding_ids": self.finding_ids,
            "asset_ids": self.asset_ids,
            "evidence": self.evidence,
            "correlation_fingerprint": self.correlation_fingerprint,
            "timeline": self.timeline,
            "notes": self.notes,
            "assigned_to": self.assigned_to
        })
        return res
