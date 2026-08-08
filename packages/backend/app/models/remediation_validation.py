import enum
from datetime import datetime
from app.database.base import BaseModel
from typing import Dict, List, Any

class ValidationStatus(str, enum.Enum):
    PENDING = "pending"
    VALIDATING = "validating"
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    NOT_FIXED = "not_fixed"
    INCONCLUSIVE = "inconclusive"

class RemediationValidation(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.remediation_id = kwargs.get("remediation_id")
        self.before_scan_id = kwargs.get("before_scan_id")
        self.after_scan_id = kwargs.get("after_scan_id")
        self.validation_status = kwargs.get("validation_status") or ValidationStatus.PENDING
        self.resolved_findings = kwargs.get("resolved_findings") or []
        self.removed_relationships = kwargs.get("removed_relationships") or []
        self.created_at = kwargs.get("created_at") or datetime.utcnow()
        self.validated_at = kwargs.get("validated_at")

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "remediation_id": str(self.remediation_id) if self.remediation_id else None,
            "before_scan_id": self.before_scan_id,
            "after_scan_id": self.after_scan_id,
            "validation_status": self.validation_status.value if hasattr(self.validation_status, 'value') else str(self.validation_status),
            "resolved_findings": self.resolved_findings,
            "removed_relationships": self.removed_relationships,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "validated_at": self.validated_at.isoformat() if isinstance(self.validated_at, datetime) else self.validated_at
        })
        return res
