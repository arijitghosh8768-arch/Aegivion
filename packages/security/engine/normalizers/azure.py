import uuid
from typing import Dict, Any
from datetime import datetime
from security.engine.normalizers.base import BaseNormalizer
from app.models.security_event import SecurityEvent, SecurityEventCategory

class AzureNormalizer(BaseNormalizer):
    
    @staticmethod
    def _map_category(operation_name: str) -> SecurityEventCategory:
        op = operation_name.lower()
        if "blob/read" in op or "blobs/read" in op:
            return SecurityEventCategory.OBJECT_READ
        if "authorization" in op and "write" in op:
            return SecurityEventCategory.PERMISSION_CHANGED
        if "delete" in op:
            return SecurityEventCategory.RESOURCE_DELETED
        if "login" in op or "sign-in" in op:
            return SecurityEventCategory.LOGIN
        return SecurityEventCategory.RESOURCE_MODIFIED

    @staticmethod
    def normalize(raw_event: Dict[str, Any], context: Dict[str, Any]) -> SecurityEvent:
        action = raw_event.get("operationName", "unknown")
        category = AzureNormalizer._map_category(action)
        
        actor = {
            "native_id": raw_event.get("caller") or "unknown"
        }
        
        target = {
            "native_id": raw_event.get("resourceId") or "unknown",
            "resource_group": raw_event.get("resourceGroupName")
        }
        
        ts_str = raw_event.get("eventTimestamp")
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
            provider="azure",
            event_type=category,
            timestamp=timestamp,
            actor=actor,
            action=action,
            target=target,
            metadata=raw_event,
            native_event_id=raw_event.get("correlationId"),
            raw_event_reference=event_id
        )
