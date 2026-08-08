import enum
from datetime import datetime
from app.database.base import BaseModel
from typing import Dict, List, Any

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    CLOSED = "closed"

class Incident(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.title = kwargs.get("title") or "Correlated Security Incident"
        self.description = kwargs.get("description") or "Security incident compiled from multiple correlated finding indicators."
        self.severity = kwargs.get("severity") or "medium"
        self.risk_score = kwargs.get("risk_score") or 50
        self.confidence = kwargs.get("confidence") or 0.80
        self.status = kwargs.get("status") or IncidentStatus.OPEN
        self.first_seen_at = kwargs.get("first_seen_at") or datetime.utcnow()
        self.last_seen_at = kwargs.get("last_seen_at") or datetime.utcnow()
        self.finding_ids = kwargs.get("finding_ids") or []
        self.asset_ids = kwargs.get("asset_ids") or []
        self.evidence = kwargs.get("evidence") or {}
        self.correlation_fingerprint = kwargs.get("correlation_fingerprint")
        self.timeline = kwargs.get("timeline") or []
        self.notes = kwargs.get("notes") or []

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "status": self.status.value if hasattr(self.status, 'value') else str(self.status),
            "first_seen_at": self.first_seen_at.isoformat() if isinstance(self.first_seen_at, datetime) else self.first_seen_at,
            "last_seen_at": self.last_seen_at.isoformat() if isinstance(self.last_seen_at, datetime) else self.last_seen_at,
            "finding_ids": self.finding_ids,
            "asset_ids": self.asset_ids,
            "evidence": self.evidence,
            "correlation_fingerprint": self.correlation_fingerprint,
            "timeline": self.timeline,
            "notes": self.notes
        })
        return res
