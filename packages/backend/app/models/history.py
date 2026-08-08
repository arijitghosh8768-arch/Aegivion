import enum
import hashlib
import json
from datetime import datetime
from app.database.base import BaseModel
from typing import Dict, Any, List, Optional

class AssetSnapshot(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.asset_id = kwargs.get("asset_id")
        self.version_number = kwargs.get("version_number") or 1
        self.configuration = kwargs.get("configuration") or {}
        self.configuration_hash = kwargs.get("configuration_hash") or self.calculate_hash(self.configuration)
        self.scan_id = kwargs.get("scan_id")
        self.created_at = kwargs.get("created_at") or datetime.utcnow()

    @staticmethod
    def calculate_hash(config: Dict[str, Any]) -> str:
        """Produce deterministic SHA-256 hash of configuration dictionary"""
        try:
            canonical_json = json.dumps(config, sort_keys=True, default=str)
            return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        except Exception:
            return "hash-fallback"

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "asset_id": self.asset_id,
            "version_number": self.version_number,
            "configuration": self.configuration,
            "configuration_hash": self.configuration_hash,
            "scan_id": self.scan_id,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at
        })
        return res

class SecurityRiskSnapshot(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.cloud_account_id = kwargs.get("cloud_account_id")
        self.scan_id = kwargs.get("scan_id")
        self.timestamp = kwargs.get("timestamp") or datetime.utcnow()
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
        self.data_source = kwargs.get("data_source") or "REAL"

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "asset_count": self.asset_count,
            "finding_count": self.finding_count,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "open_incidents": self.open_incidents,
            "critical_attack_paths": self.critical_attack_paths,
            "high_attack_paths": self.high_attack_paths,
            "compliance_pass_rate": self.compliance_pass_rate,
            "overall_risk": self.overall_risk,
            "data_source": self.data_source
        })
        return res

class FindingSuppression(BaseModel):
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

    def dict(self) -> Dict[str, Any]:
        from datetime import timedelta
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "finding_id": str(self.finding_id),
            "reason": self.reason,
            "created_by": self.created_by,
            "approved_by": self.approved_by,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "expires_at": self.expires_at.isoformat() if isinstance(self.expires_at, datetime) else self.expires_at,
            "status": self.status
        })
        return res

class SecurityChange(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.asset_id = kwargs.get("asset_id")
        self.change_type = kwargs.get("change_type") or "CHANGED"
        self.field = kwargs.get("field")
        self.old_value = kwargs.get("old_value")
        self.new_value = kwargs.get("new_value")
        self.security_relevance = kwargs.get("security_relevance") or "LOW"
        self.security_category = kwargs.get("security_category") or "PUBLIC_EXPOSURE"
        self.detected_at = kwargs.get("detected_at") or datetime.utcnow()

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "asset_id": self.asset_id,
            "change_type": self.change_type,
            "field": self.field,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "security_relevance": self.security_relevance,
            "security_category": self.security_category,
            "detected_at": self.detected_at.isoformat() if isinstance(self.detected_at, datetime) else self.detected_at
        })
        return res

class SyncQuality(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.sync_id = kwargs.get("sync_id") or f"SYNC-{uuid.uuid4().hex[:6].upper()}"
        self.status = kwargs.get("status") or "SUCCESS"
        self.assets_discovered = kwargs.get("assets_discovered") or 0
        self.assets_normalized = kwargs.get("assets_normalized") or 0
        self.collection_errors = kwargs.get("collection_errors") or 0
        self.unsupported_resources = kwargs.get("unsupported_resources") or 0
        self.last_successful_sync = kwargs.get("last_successful_sync") or datetime.utcnow()
        self.freshness = kwargs.get("freshness") or "FRESH"

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "sync_id": self.sync_id,
            "status": self.status,
            "assets_discovered": self.assets_discovered,
            "assets_normalized": self.assets_normalized,
            "collection_errors": self.collection_errors,
            "unsupported_resources": self.unsupported_resources,
            "last_successful_sync": self.last_successful_sync.isoformat() if isinstance(self.last_successful_sync, datetime) else self.last_successful_sync,
            "freshness": self.freshness
        })
        return res



