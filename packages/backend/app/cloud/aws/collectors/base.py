from typing import Any, Optional, Dict, List
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field

class UnknownValue:
    """Explicit unknown value to distinguish from None/False"""
    def __bool__(self):
        return False
    def __repr__(self):
        return "UNKNOWN"

UNKNOWN = UnknownValue()

class AssetEnvelope(BaseModel):
    """Standardized asset envelope for all collectors"""
    asset_id: str = Field(..., description="Unique asset identifier")
    provider: str = Field(..., description="Cloud provider (aws, azure, gcp)")
    account_id: str = Field(..., description="Cloud account ID")
    resource_type: str = Field(..., description="Normalized resource type")
    type: str = Field(..., description="Type of resource (mapped from resource_type for contract validation)")
    region: Optional[str] = Field(None, description="Region (global for IAM)")
    arn: Optional[str] = Field(None, description="AWS ARN if available")
    name: Optional[str] = Field(None, description="Resource name")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Resource configuration")
    relationships: list = Field(default_factory=list, description="Resource relationships")
    collected_at: str = Field(..., description="ISO-8601 UTC timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

class BaseCollector:
    """Base collector with hardening and unknown handling"""
    
    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.region = region
        self.collector_name = "base"
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Override in subclasses"""
        raise NotImplementedError
    
    def _safe_get(self, data: Dict, path: str, default: Any = UNKNOWN) -> Any:
        """Safely get nested value with explicit unknown handling"""
        parts = path.split('.')
        current = data
        
        for part in parts:
            if isinstance(current, dict):
                if part not in current:
                    return default if default is not None else UNKNOWN
                current = current[part]
            else:
                return default if default is not None else UNKNOWN
        
        return current if current is not None else default
    
    def _normalize_timestamp(self, timestamp) -> Optional[str]:
        """Normalize timestamp to ISO-8601 UTC"""
        if timestamp is None:
            return None
        if isinstance(timestamp, datetime):
            return timestamp.isoformat()
        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.isoformat()
            except:
                return None
        return None
    
    def _build_envelope(self, **kwargs) -> AssetEnvelope:
        """Build standardized asset envelope"""
        resource_type = kwargs.get('resource_type')
        return AssetEnvelope(
            asset_id=kwargs.get('asset_id'),
            provider=kwargs.get('provider', 'aws'),
            account_id=kwargs.get('account_id'),
            resource_type=resource_type,
            type=resource_type,
            region=kwargs.get('region'),
            arn=kwargs.get('arn'),
            name=kwargs.get('name'),
            configuration=kwargs.get('configuration', {}),
            relationships=kwargs.get('relationships', []),
            collected_at=datetime.utcnow().isoformat(),
            metadata=kwargs.get('metadata', {})
        )
