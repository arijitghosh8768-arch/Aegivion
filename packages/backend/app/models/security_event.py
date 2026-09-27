import enum
import hashlib
import json
from datetime import datetime
from typing import Dict, Any, Optional
from app.database.base import BaseModel

class SecurityEventCategory(str, enum.Enum):
    # Identity
    LOGIN = "LOGIN"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    TOKEN_USE = "TOKEN_USE"
    ROLE_ASSUMED = "ROLE_ASSUMED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    IDENTITY_CREATED = "IDENTITY_CREATED"
    IDENTITY_DELETED = "IDENTITY_DELETED"
    
    # Data
    OBJECT_READ = "OBJECT_READ"
    OBJECT_DOWNLOAD = "OBJECT_DOWNLOAD"
    DATABASE_READ = "DATABASE_READ"
    DATA_EXPORT = "DATA_EXPORT"
    LARGE_TRANSFER = "LARGE_TRANSFER"
    
    # Network
    CONNECTION = "CONNECTION"
    PORT_EXPOSURE = "PORT_EXPOSURE"
    SECURITY_GROUP_CHANGED = "SECURITY_GROUP_CHANGED"
    FIREWALL_CHANGED = "FIREWALL_CHANGED"
    PUBLIC_ACCESS_ENABLED = "PUBLIC_ACCESS_ENABLED"
    
    # Resource
    RESOURCE_CREATED = "RESOURCE_CREATED"
    RESOURCE_MODIFIED = "RESOURCE_MODIFIED"
    RESOURCE_DELETED = "RESOURCE_DELETED"
    
    # Destructive
    MASS_DELETE = "MASS_DELETE"
    BACKUP_DELETED = "BACKUP_DELETED"
    SNAPSHOT_DELETED = "SNAPSHOT_DELETED"
    MASS_MODIFICATION = "MASS_MODIFICATION"
    ENCRYPTION_ACTIVITY = "ENCRYPTION_ACTIVITY"


class SecurityEvent(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.event_id = kwargs.get("event_id")
        self.organization_id = kwargs.get("organization_id")
        self.account_id = kwargs.get("account_id")
        self.provider = kwargs.get("provider")
        self.event_type = kwargs.get("event_type")
        self.timestamp = kwargs.get("timestamp") or datetime.utcnow()
        
        self.actor = kwargs.get("actor") or {}
        self.action = kwargs.get("action")
        self.target = kwargs.get("target") or {}
        self.source = kwargs.get("source") or {}
        self.metadata = kwargs.get("metadata") or {}
        
        self.native_event_id = kwargs.get("native_event_id")
        self.raw_event_reference = kwargs.get("raw_event_reference")
        
        self.event_fingerprint = kwargs.get("event_fingerprint") or self._generate_fingerprint()

    def _generate_fingerprint(self) -> str:
        """Deduplication strategy: prefer native event ID, otherwise hash deterministic fields."""
        if self.native_event_id:
            raw = f"{self.provider}:{self.account_id}:{self.native_event_id}"
        else:
            raw = f"{self.provider}:{self.account_id}:{self.event_type}:{self.timestamp}:{json.dumps(self.actor, sort_keys=True)}:{self.action}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def dict(self) -> Dict[str, Any]:
        res = super().dict()
        res.update({
            "event_id": self.event_id,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "account_id": str(self.account_id) if self.account_id else None,
            "provider": self.provider,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "source": self.source,
            "metadata": self.metadata,
            "native_event_id": self.native_event_id,
            "raw_event_reference": self.raw_event_reference,
            "event_fingerprint": self.event_fingerprint
        })
        return res
