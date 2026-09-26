from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime

class SecurityEventSchema(BaseModel):
    """Canonical normalized event contract"""
    event_id: str
    organization_id: str
    cloud_account_id: str
    provider: str
    timestamp: datetime
    
    # Core 5-tuple
    actor: str
    action: str
    target: str
    source: str
    
    # Additional Context
    status: str = "success"  # success, failed
    metadata: Dict[str, Any] = Field(default_factory=dict)
