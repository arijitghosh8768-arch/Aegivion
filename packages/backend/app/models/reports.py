import enum
from datetime import datetime
from app.database.base import BaseModel
from typing import Dict, List, Any, Optional

class ReportType(str, enum.Enum):
    EXECUTIVE = "EXECUTIVE"
    TECHNICAL = "TECHNICAL"
    COMPLIANCE = "COMPLIANCE"

class ReportStatus(str, enum.Enum):
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class SecurityPostureSnapshot(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.scan_id = kwargs.get("scan_id")
        self.snapshot_version = kwargs.get("snapshot_version") or "0.4.0"
        self.created_at = kwargs.get("created_at") or datetime.utcnow()
        self.coverage_status = kwargs.get("coverage_status") or "PARTIAL"
        
        # Aggregated snapshot values
        self.assets = kwargs.get("assets") or {"total": 0, "high_risk": 0}
        self.findings = kwargs.get("findings") or {"critical": 0, "high": 0, "medium": 0, "low": 0}
        self.incidents = kwargs.get("incidents") or {"open": 0, "investigating": 0}
        self.attack_paths = kwargs.get("attack_paths") or {"critical": 0, "high": 0}
        self.remediation = kwargs.get("remediation") or {"open": 0, "verified": 0}
        self.compliance = kwargs.get("compliance") or {"pass": 0, "fail": 0, "not_assessed": 0}

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "scan_id": self.scan_id,
            "snapshot_version": self.snapshot_version,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "coverage_status": self.coverage_status,
            "assets": self.assets,
            "findings": self.findings,
            "incidents": self.incidents,
            "attack_paths": self.attack_paths,
            "remediation": self.remediation,
            "compliance": self.compliance
        })
        return res

class GeneratedReport(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.snapshot_id = kwargs.get("snapshot_id")
        self.report_type = kwargs.get("report_type") or ReportType.EXECUTIVE
        self.status = kwargs.get("status") or ReportStatus.COMPLETED
        self.title = kwargs.get("title")
        self.content = kwargs.get("content") or {}
        self.created_at = kwargs.get("created_at") or datetime.utcnow()

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "snapshot_id": self.snapshot_id,
            "report_type": self.report_type.value if hasattr(self.report_type, 'value') else str(self.report_type),
            "status": self.status.value if hasattr(self.status, 'value') else str(self.status),
            "title": self.title,
            "content": self.content,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at
        })
        return res
