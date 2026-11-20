from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.database.base import BaseModel, LegacyBaseModel as OrmBaseModel

# Worker state lives in real PostgreSQL tables (migration b0011). These were
# previously declared as legacy mock classes, so any ORM query raised
# AttributeError ('MockField' object has no attribute '_post_inspect').
class AgentHeartbeat(BaseModel):
    __tablename__ = "agent_heartbeats"

    organization_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    worker = Column(String(50), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="RUNNING")
    last_heartbeat = Column(String(64), nullable=True)
    current_activity = Column(String(255), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.worker = kwargs.get("worker", "discovery")
        self.status = kwargs.get("status", "RUNNING")
        self.last_heartbeat = kwargs.get(
            "last_heartbeat", datetime.now(timezone.utc).isoformat()
        )
        self.current_activity = kwargs.get("current_activity", "Idle")
        
    def dict(self):
        d = super().dict()
        d.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "worker": self.worker,
            "status": self.status,
            "last_heartbeat": self.last_heartbeat,
            "current_activity": self.current_activity,
        })
        return d

class ResponseExecution(BaseModel):
    __tablename__ = "response_executions"

    organization_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    runbook_id = Column(UUID(as_uuid=True), nullable=True)
    finding_id = Column(UUID(as_uuid=True), nullable=True)
    asset_id = Column(UUID(as_uuid=True), nullable=True)
    provider = Column(String(50), nullable=True)
    action_type = Column(String(100), nullable=True)
    resource_id = Column(String(255), nullable=True)
    status = Column(String(30), nullable=False, default="QUEUED", index=True)
    verification_status = Column(String(30), nullable=False, default="PENDING")
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    executed_by = Column(UUID(as_uuid=True), nullable=True)
    details = Column(JSONB, nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.runbook_id = kwargs.get("runbook_id")
        self.finding_id = kwargs.get("finding_id")
        self.asset_id = kwargs.get("asset_id")
        self.provider = kwargs.get("provider")
        self.action_type = kwargs.get("action_type")
        self.status = kwargs.get("status", "QUEUED")
        self.verification_status = kwargs.get("verification_status", "PENDING")
        self.created_by = kwargs.get("created_by")
        self.created_at = kwargs.get("created_at", datetime.now(timezone.utc))
        self.completed_at = kwargs.get("completed_at")
        self.details = kwargs.get("details", {})
        
    def dict(self):
        d = super().dict()
        d.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "runbook_id": str(self.runbook_id) if self.runbook_id else None,
            "finding_id": str(self.finding_id) if self.finding_id else None,
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "provider": self.provider,
            "action_type": self.action_type,
            "status": self.status,
            "verification_status": self.verification_status,
            "created_by": str(self.created_by) if self.created_by else None,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "details": self.details,
        })
        return d

class PendingApproval(OrmBaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.finding_id = kwargs.get("finding_id")
        self.candidate_id = kwargs.get("candidate_id")
        self.runbook_id = kwargs.get("runbook_id")
        self.status = kwargs.get("status", "PENDING")  # PENDING, APPROVED, REJECTED
        self.risk_score = kwargs.get("risk_score", 0)
        self.confidence = kwargs.get("confidence", 0)
        self.business_impact = kwargs.get("business_impact", "LOW")
        self.blast_radius = kwargs.get("blast_radius", "LOW")
        self.created_at = kwargs.get("created_at", datetime.utcnow().isoformat())
        self.reviewed_by = kwargs.get("reviewed_by")
        self.reviewed_at = kwargs.get("reviewed_at")
        
    def dict(self):
        d = super().dict()
        d.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "finding_id": str(self.finding_id) if self.finding_id else None,
            "candidate_id": str(self.candidate_id) if self.candidate_id else None,
            "runbook_id": str(self.runbook_id) if self.runbook_id else None,
            "status": self.status,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "business_impact": self.business_impact,
            "blast_radius": self.blast_radius,
            "created_at": self.created_at,
            "reviewed_by": str(self.reviewed_by) if self.reviewed_by else None,
            "reviewed_at": self.reviewed_at,
        })
        return d
