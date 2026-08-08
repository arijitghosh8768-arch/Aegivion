import enum
from datetime import datetime
from app.database.base import BaseModel
from typing import Dict, List, Any, Optional

class ComplianceStatus(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"

class ComplianceControlResult(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.control_code = kwargs.get("control_code")
        self.framework_id = kwargs.get("framework_id") or "CIS_AWS_v3"
        self.title = kwargs.get("title")
        self.category = kwargs.get("category")
        self.severity = kwargs.get("severity") or "high"
        self.status = kwargs.get("status") or ComplianceStatus.NOT_ASSESSED
        self.affected_resources = kwargs.get("affected_resources") or []
        self.evidence_refs = kwargs.get("evidence_refs") or []
        self.finding_refs = kwargs.get("finding_refs") or []
        self.assessed_at = kwargs.get("assessed_at") or datetime.utcnow()
        self.scan_id = kwargs.get("scan_id")

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "control_code": self.control_code,
            "framework_id": self.framework_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status.value if hasattr(self.status, 'value') else str(self.status),
            "affected_resources": self.affected_resources,
            "evidence_refs": self.evidence_refs,
            "finding_refs": self.finding_refs,
            "assessed_at": self.assessed_at.isoformat() if isinstance(self.assessed_at, datetime) else self.assessed_at,
            "scan_id": self.scan_id
        })
        return res
