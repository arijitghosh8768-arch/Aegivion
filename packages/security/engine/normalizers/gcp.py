import uuid
from typing import Dict, Any
from datetime import datetime
from security.engine.normalizers.base import BaseNormalizer
from app.models.security_event import SecurityEvent, SecurityEventCategory

class GCPNormalizer(BaseNormalizer):
    
    @staticmethod
    def _map_category(method_name: str) -> SecurityEventCategory:
        method = method_name.lower()
        if "storage.objects.get" in method or "storage.objects.list" in method or "storage.object.read" in method:
            return SecurityEventCategory.OBJECT_READ
        if "setiam" in method or "setiampolicy" in method:
            return SecurityEventCategory.PERMISSION_CHANGED
        if "delete" in method:
            return SecurityEventCategory.RESOURCE_DELETED
        if "create" in method or "insert" in method:
            return SecurityEventCategory.RESOURCE_CREATED
        if "login" in method:
            return SecurityEventCategory.LOGIN
        return SecurityEventCategory.RESOURCE_MODIFIED

    @staticmethod
    def normalize(raw_event: Dict[str, Any], context: Dict[str, Any]) -> SecurityEvent:
        proto_payload = raw_event.get("protoPayload", {})
        action = proto_payload.get("methodName") or raw_event.get("methodName") or "unknown"
        category = GCPNormalizer._map_category(action)
        
        authentication_info = proto_payload.get("authenticationInfo", {})
        actor = {
            "native_id": authentication_info.get("principalEmail") or "unknown"
        }
        
        target = {
            "native_id": proto_payload.get("resourceName") or raw_event.get("resourceName") or "unknown",
            "service": proto_payload.get("serviceName")
        }
        
        source = {
            "ip": proto_payload.get("requestMetadata", {}).get("callerIp")
        }
        
        ts_str = raw_event.get("timestamp")
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
            provider="gcp",
            event_type=category,
            timestamp=timestamp,
            actor=actor,
            action=action,
            target=target,
            source=source,
            metadata=raw_event,
            native_event_id=raw_event.get("insertId"),
            raw_event_reference=event_id
        )
