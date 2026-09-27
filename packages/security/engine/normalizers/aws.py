import uuid
from typing import Dict, Any
from datetime import datetime
from security.engine.normalizers.base import BaseNormalizer
from app.models.security_event import SecurityEvent, SecurityEventCategory

class AWSNormalizer(BaseNormalizer):
    
    _CATEGORY_MAP = {
        "ConsoleLogin": SecurityEventCategory.LOGIN,
        "AssumeRole": SecurityEventCategory.ROLE_ASSUMED,
        "GetObject": SecurityEventCategory.OBJECT_READ,
        "PutObject": SecurityEventCategory.RESOURCE_MODIFIED,
        "DeleteObject": SecurityEventCategory.RESOURCE_DELETED,
        "CreateUser": SecurityEventCategory.IDENTITY_CREATED,
        "CreateRole": SecurityEventCategory.IDENTITY_CREATED,
        "AttachRolePolicy": SecurityEventCategory.PERMISSION_CHANGED,
        "PutRolePolicy": SecurityEventCategory.PERMISSION_CHANGED,
        "AuthorizeSecurityGroupIngress": SecurityEventCategory.SECURITY_GROUP_CHANGED,
        "RevokeSecurityGroupIngress": SecurityEventCategory.SECURITY_GROUP_CHANGED,
        "DeleteSecurityGroup": SecurityEventCategory.RESOURCE_DELETED,
        "DeleteSnapshot": SecurityEventCategory.SNAPSHOT_DELETED,
    }

    @staticmethod
    def normalize(raw_event: Dict[str, Any], context: Dict[str, Any]) -> SecurityEvent:
        action = raw_event.get("eventName", "unknown")
        category = AWSNormalizer._CATEGORY_MAP.get(action, SecurityEventCategory.RESOURCE_MODIFIED) # conservative default
        
        # Identity
        user_identity = raw_event.get("userIdentity", {})
        actor = {
            "native_id": user_identity.get("arn") or user_identity.get("principalId") or "unknown",
            "type": user_identity.get("type", "unknown")
        }
        
        # Source
        source = {
            "ip": raw_event.get("sourceIPAddress"),
            "region": raw_event.get("awsRegion")
        }
        
        # Target
        resources = raw_event.get("resources", [])
        target = {}
        if resources:
            target = {
                "native_id": resources[0].get("ARN") or resources[0].get("accountId") or "unknown",
                "type": resources[0].get("type", "unknown")
            }
            
        ts_str = raw_event.get("eventTime")
        if ts_str:
            try:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()
            
        event_id = str(uuid.uuid4())
            
        return SecurityEvent(
            event_id=event_id,
            organization_id=context.get("organization_id"),
            account_id=context.get("account_id"),
            provider="aws",
            event_type=category,
            timestamp=timestamp,
            actor=actor,
            action=action,
            target=target,
            source=source,
            metadata=raw_event,
            native_event_id=raw_event.get("eventID"),
            raw_event_reference=event_id
        )
