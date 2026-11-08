import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.models.postgres_base import PostgresBase


class RemediationPlan(PostgresBase):
    __tablename__ = "remediation_plans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True)
    resource_id = Column(String(255), nullable=False, index=True)
    status = Column(String(50), nullable=False, default="PENDING_APPROVAL", index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    idempotency_key = Column(String(128), nullable=True, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    actions = relationship("RemediationAction", back_populates="plan", cascade="all, delete-orphan")
    audit_logs = relationship("RemediationAuditLog", back_populates="plan", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "finding_id": str(self.finding_id) if self.finding_id else None,
            "resource_id": self.resource_id,
            "status": self.status,
            "created_by": str(self.created_by) if self.created_by else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "idempotency_key": self.idempotency_key,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "actions": [a.to_dict() for a in self.actions] if self.actions else []
        }


class RemediationAction(PostgresBase):
    __tablename__ = "remediation_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    plan_id = Column(UUID(as_uuid=True), ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(100), nullable=False)
    parameters = Column(JSONB, default=dict, nullable=False)
    rollback_payload = Column(JSONB, default=dict, nullable=False)
    status = Column(String(50), nullable=False, default="PENDING", index=True)
    aws_request_id = Column(String(128), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    plan = relationship("RemediationPlan", back_populates="actions")

    def to_dict(self):
        return {
            "id": str(self.id),
            "plan_id": str(self.plan_id),
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "action_type": self.action_type,
            "parameters": self.parameters or {},
            "rollback_payload": self.rollback_payload or {},
            "status": self.status,
            "aws_request_id": self.aws_request_id,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class RemediationAuditLog(PostgresBase):
    __tablename__ = "remediation_audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id = Column(UUID(as_uuid=True), ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=True, index=True)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(JSONB, default=dict, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    plan = relationship("RemediationPlan", back_populates="audit_logs")

    def to_dict(self):
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "plan_id": str(self.plan_id) if self.plan_id else None,
            "actor_id": str(self.actor_id) if self.actor_id else None,
            "action": self.action,
            "details": self.details or {},
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

