import enum
from datetime import datetime
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
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.title = kwargs.get("title")
        self.description = kwargs.get("description")
        self.severity = kwargs.get("severity") or FindingSeverity.MEDIUM
        self.status = kwargs.get("status") or FindingStatus.OPEN
        self.source = kwargs.get("source") or FindingSource.CSPM
        self.resource_id = kwargs.get("resource_id")
        self.resource_name = kwargs.get("resource_name")
        self.resource_type = kwargs.get("resource_type")
        self.resource_region = kwargs.get("resource_region")
        self.cloud_provider = kwargs.get("cloud_provider")
        self.rule_id = kwargs.get("rule_id")
        self.rule_name = kwargs.get("rule_name")
        self.risk_score = kwargs.get("risk_score")
        self.cvss_score = kwargs.get("cvss_score")
        self.remediation_steps = kwargs.get("remediation_steps") or {}
        self.evidence = kwargs.get("evidence") or {}
        self.evidence_source = kwargs.get("evidence_source") or "aws_api"
        self.evidence_collected_at = kwargs.get("evidence_collected_at") or datetime.utcnow()
        self.evidence_confidence = kwargs.get("evidence_confidence") or "HIGH"
        self.evidence_quality_score = kwargs.get("evidence_quality_score") or 90.0
        self.tags = kwargs.get("tags") or []
        self.assigned_to_id = kwargs.get("assigned_to_id")
        self.assigned_to = kwargs.get("assigned_to")
        self.notes = kwargs.get("notes") or []
        self.timeline = kwargs.get("timeline") or []
        self.resolved_at = kwargs.get("resolved_at")
        self.resolved_by_id = kwargs.get("resolved_by_id")

    def calculate_risk_score(self) -> float:
        severity_scores = {
            FindingSeverity.CRITICAL: 10.0,
            FindingSeverity.HIGH: 7.5,
            FindingSeverity.MEDIUM: 5.0,
            FindingSeverity.LOW: 2.5,
            FindingSeverity.INFO: 1.0
        }
        sev = self.severity
        if isinstance(sev, str):
            try:
                sev = FindingSeverity(sev)
            except Exception:
                sev = FindingSeverity.MEDIUM
        base_score = severity_scores.get(sev, 5.0)
        return base_score

    def dict(self):
        res = super().dict()
        res.update({
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
            "resolved_by_id": str(self.resolved_by_id) if self.resolved_by_id else None
        })
        return res

