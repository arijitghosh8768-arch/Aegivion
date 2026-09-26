from typing import Dict, Any
from security.models.security_event_schema import SecurityEventSchema
import uuid
from datetime import datetime

class SecurityEventNormalizer:
    """Base normalizer to transform provider events into the canonical SecurityEventSchema"""
    
    @staticmethod
    def normalize(provider: str, raw_event: Dict[str, Any], organization_id: str) -> SecurityEventSchema:
        """Entry point for normalization"""
        if provider.lower() == "aws":
            return SecurityEventNormalizer._normalize_aws(raw_event, organization_id)
        # Extend with GCP/Azure later
        raise NotImplementedError(f"Normalizer for provider {provider} is not implemented")
        
    @staticmethod
    def _normalize_aws(raw_event: Dict[str, Any], organization_id: str) -> SecurityEventSchema:
        user_identity = raw_event.get("userIdentity", {})
        actor = user_identity.get("arn") or user_identity.get("userName") or "unknown"
        
        resources = raw_event.get("resources", [])
        target = resources[0].get("ARN") if resources else "unknown"
        
        event_time_str = raw_event.get("eventTime")
        if event_time_str:
            try:
                timestamp = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()
            
        # cloud_account_id mapping
        account_id = raw_event.get("recipientAccountId") or "unknown"
        
        # Determine fingerprint hash if no eventID
        import hashlib
        event_id = raw_event.get("eventID")
        if not event_id:
            raw_hash = f"{actor}-{raw_event.get('eventName')}-{target}-{timestamp}"
            event_id = hashlib.sha256(raw_hash.encode()).hexdigest()
            
        return SecurityEventSchema(
            event_id=event_id,
            organization_id=organization_id,
            cloud_account_id=account_id,
            provider="aws",
            timestamp=timestamp,
            actor=actor,
            action=raw_event.get("eventName", "unknown"),
            target=target,
            source=raw_event.get("eventSource", "unknown"),
            status="failed" if raw_event.get("errorCode") else "success",
            metadata=raw_event
        )
