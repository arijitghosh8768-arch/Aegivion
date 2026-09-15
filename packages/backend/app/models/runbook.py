from typing import Dict, Any, Optional
from datetime import datetime
from app.database.base import BaseModel as OrmBaseModel

class Runbook(OrmBaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.name = kwargs.get("name", "New Runbook")
        self.description = kwargs.get("description", "")
        self.provider = kwargs.get("provider", "MULTI_CLOUD")
        self.trigger_type = kwargs.get("trigger_type", "Finding detected")
        self.trigger_conditions = kwargs.get("trigger_conditions", {})
        self.severity = kwargs.get("severity", "medium")
        self.mode = kwargs.get("mode", "APPROVAL_REQUIRED")
        self.enabled = kwargs.get("enabled", True)
        self.status = kwargs.get("status", "ACTIVE" if self.enabled else "PAUSED")
        self.safety_policy = kwargs.get("safety_policy", {
            "confidence_threshold": 90,
            "max_blast_radius": "LOW",
            "require_approval": True,
            "must_be_reversible": True
        })
        self.created_by = kwargs.get("created_by")
        self.created_at = kwargs.get("created_at", datetime.utcnow().isoformat())
        self.updated_at = kwargs.get("updated_at", datetime.utcnow().isoformat())
        
        # Legacy frontend compatibility
        self.trigger = kwargs.get("trigger", self.trigger_type)
        self.action = kwargs.get("action", "Alert")
        self.runs = kwargs.get("runs", 0)
        self.last_run = kwargs.get("last_run", "Never")
        self.target_url = kwargs.get("target_url", "/remediation")
        self.accent = kwargs.get("accent", "bg-brand-blue/12 text-brand-blue")

    def dict(self):
        d = super().dict()
        d.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "name": self.name,
            "description": self.description,
            "provider": self.provider,
            "trigger_type": self.trigger_type,
            "trigger_conditions": self.trigger_conditions,
            "severity": self.severity,
            "mode": self.mode,
            "enabled": self.enabled,
            "status": self.status,
            "safety_policy": self.safety_policy,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            # Legacy fields for UI compatibility until UI is updated
            "trigger": self.trigger,
            "action": self.action,
            "runs": self.runs,
            "lastRun": self.last_run,
            "target": self.target_url,
            "accent": self.accent
        })
        return d
