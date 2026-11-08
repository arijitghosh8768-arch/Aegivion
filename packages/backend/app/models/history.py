import enum
import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database.base import BaseModel, LegacyBaseModel

class AssetSnapshot(BaseModel):
    __tablename__ = "asset_snapshots"

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    cloud_account_id = Column(UUID(as_uuid=True), ForeignKey("cloud_accounts_v2.id", ondelete="SET NULL"), nullable=True)
    asset_id = Column(String(300), nullable=False)
    version_number = Column(Integer, default=1, nullable=False)
    configuration = Column(JSONB, default=dict)
    configuration_hash = Column(String(64), nullable=False, index=True)
    scan_id = Column(String(100), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.asset_id = kwargs.get("asset_id")
        self.version_number = kwargs.get("version_number") or 1
        self.configuration = kwargs.get("configuration") or {}
        self.configuration_hash = kwargs.get("configuration_hash") or self.calculate_hash(self.configuration)
        self.scan_id = kwargs.get("scan_id")

    @staticmethod
    def calculate_hash(config: Dict[str, Any]) -> str:
        """Produce deterministic SHA-256 hash of configuration dictionary"""
        try:
            canonical_json = json.dumps(config, sort_keys=True, default=str)
            return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        except Exception:
            return "hash-fallback"

    def dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id) if self.id else None,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "asset_id": self.asset_id,
            "version_number": self.version_number,
            "configuration": self.configuration,
            "configuration_hash": self.configuration_hash,
            "scan_id": self.scan_id,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at
        }

class SecurityRiskSnapshot(BaseModel):
    __tablename__ = "security_risk_snapshots"

    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    cloud_account_id = Column(UUID(as_uuid=True), ForeignKey("cloud_accounts_v2.id", ondelete="SET NULL"), nullable=True)
    scan_id = Column(String(100), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    asset_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    open_incidents = Column(Integer, default=0)
    critical_attack_paths = Column(Integer, default=0)
    high_attack_paths = Column(Integer, default=0)
    compliance_pass_rate = Column(Integer, default=0)
    overall_risk = Column(Integer, default=0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.scan_id = kwargs.get("scan_id")
        self.timestamp = kwargs.get("timestamp") or datetime.now(timezone.utc)
        self.asset_count = kwargs.get("asset_count") or 0
        self.finding_count = kwargs.get("finding_count") or 0
        self.critical_findings = kwargs.get("critical_findings") or 0
        self.high_findings = kwargs.get("high_findings") or 0
        self.medium_findings = kwargs.get("medium_findings") or 0
        self.low_findings = kwargs.get("low_findings") or 0
        self.open_incidents = kwargs.get("open_incidents") or 0
        self.critical_attack_paths = kwargs.get("critical_attack_paths") or 0
        self.high_attack_paths = kwargs.get("high_attack_paths") or 0
        self.compliance_pass_rate = kwargs.get("compliance_pass_rate") or 0
        self.overall_risk = kwargs.get("overall_risk") or 0

class FindingSuppression(LegacyBaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.finding_id = kwargs.get("finding_id")
        self.reason = kwargs.get("reason") or "Approved temporary risk acceptance"
        self.created_by = kwargs.get("created_by") or "system"
        self.approved_by = kwargs.get("approved_by") or "security_admin"
        self.created_at = kwargs.get("created_at") or datetime.utcnow()
        self.expires_at = kwargs.get("expires_at") or (datetime.utcnow() + timedelta(days=30))
        self.status = kwargs.get("status") or "ACTIVE"

class SecurityChange(LegacyBaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.change_type = kwargs.get("change_type")
        self.details = kwargs.get("details") or {}

class SyncQuality(LegacyBaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.score = kwargs.get("score") or 100

class EvaluationResult(LegacyBaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.result = kwargs.get("result") or {}
