from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field, validator

class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"

class FindingEvidence(BaseModel):
    """Structured evidence for a finding"""
    protocol: Optional[str] = Field(None, description="Network protocol")
    port: Optional[int] = Field(None, description="Network port", ge=0, le=65535)
    source: Optional[str] = Field(None, description="Source IP/CIDR")
    direction: Optional[str] = Field(None, description="Rule direction")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional evidence details")

class FindingSchema(BaseModel):
    """Complete finding schema v1"""
    finding_id: str = Field(..., description="Unique finding ID")
    rule_id: str = Field(..., description="Rule that generated this finding")
    
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Finding description")
    
    provider: str = Field(..., description="Cloud provider")
    service: str = Field(..., description="AWS service")
    
    asset_id: str = Field(..., description="Affected asset ID")
    asset_name: Optional[str] = Field(None, description="Asset name")
    
    severity: FindingSeverity = Field(..., description="Finding severity")
    risk_score: Optional[int] = Field(None, description="0-100 risk score", ge=0, le=100)
    
    evidence: FindingEvidence = Field(..., description="Supporting evidence")
    
    status: FindingStatus = Field(FindingStatus.OPEN, description="Finding status")
    
    mitre_techniques: Optional[List[str]] = Field(None, description="MITRE ATT&CK techniques")
    
    remediation_summary: Optional[str] = Field(None, description="Remediation guidance")
    
    first_seen: str = Field(..., description="ISO-8601 UTC timestamp")
    last_seen: str = Field(..., description="ISO-8601 UTC timestamp")
    
    tags: Optional[List[str]] = Field(default=None, description="Finding tags")
    
    @validator('finding_id')
    def validate_finding_id(cls, v):
        import re
        pattern = r'^F-[0-9]{4,6}$'
        if not re.match(pattern, v):
            raise ValueError('Finding ID must match pattern: F-1001')
        return v
    
    @validator('first_seen', 'last_seen')
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
            return v
        except:
            raise ValueError('Timestamp must be ISO-8601 format')
    
    class Config:
        use_enum_values = True

# Finding Schema JSON Schema
FINDING_SCHEMA_JSON = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["finding_id", "rule_id", "title", "description", "provider", "service", "asset_id", "severity", "evidence", "first_seen", "last_seen"],
    "properties": {
        "finding_id": {"type": "string", "pattern": "^F-[0-9]{4,6}$"},
        "rule_id": {"type": "string"},
        "title": {"type": "string", "minLength": 5, "maxLength": 100},
        "description": {"type": "string", "minLength": 10},
        "provider": {"type": "string"},
        "service": {"type": "string"},
        "asset_id": {"type": "string"},
        "asset_name": {"type": "string"},
        "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "evidence": {
            "type": "object",
            "properties": {
                "protocol": {"type": "string"},
                "port": {"type": "integer", "minimum": 0, "maximum": 65535},
                "source": {"type": "string"},
                "direction": {"type": "string"},
                "details": {"type": "object"}
            }
        },
        "status": {"enum": ["open", "investigating", "mitigated", "resolved", "suppressed", "false_positive"]},
        "mitre_techniques": {"type": "array", "items": {"type": "string"}},
        "remediation_summary": {"type": "string"},
        "first_seen": {"type": "string", "format": "date-time"},
        "last_seen": {"type": "string", "format": "date-time"},
        "tags": {"type": "array", "items": {"type": "string"}}
    }
}
