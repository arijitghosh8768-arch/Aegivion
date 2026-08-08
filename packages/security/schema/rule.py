from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, validator

class Provider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

class ResourceType(str, Enum):
    # Compute
    EC2_INSTANCE = "ec2_instance"
    LAMBDA = "lambda_function"
    
    # Storage
    S3_BUCKET = "s3_bucket"
    
    # Identity
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    
    # Network
    SECURITY_GROUP = "security_group"
    VPC = "vpc"
    SUBNET = "subnet"
    
    # Database
    RDS_INSTANCE = "rds_instance"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Operator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IN = "in"
    NOT_IN = "not_in"
    REGEX = "regex"
    NETWORK_EXPOSURE = "network_exposure"  # Specialized operator

class Condition(BaseModel):
    field: str = Field(..., description="Field path in configuration")
    operator: Operator = Field(..., description="Operator to apply")
    value: Any = Field(None, description="Value to compare against")
    
    @validator('field')
    def validate_field(cls, v):
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v

class Remediation(BaseModel):
    summary: str = Field(..., description="Summary of remediation action")
    steps: Optional[List[str]] = Field(default=None, description="Detailed steps")
    references: Optional[List[str]] = Field(default=None, description="Reference links")

class RuleSchema(BaseModel):
    id: str = Field(..., description="Unique rule ID (e.g., AWS-SG-001)")
    version: int = Field(1, description="Rule version", ge=1)
    enabled: bool = Field(True, description="Whether rule is enabled")
    
    title: str = Field(..., description="Rule title", min_length=5, max_length=100)
    description: str = Field(..., description="Rule description", min_length=10)
    
    provider: Provider = Field(..., description="Cloud provider")
    service: str = Field(..., description="AWS service name")
    resource_type: ResourceType = Field(..., description="Resource type")
    
    severity: Severity = Field(..., description="Finding severity")
    
    condition: Condition = Field(..., description="Rule condition")
    
    remediation: Optional[Remediation] = Field(None, description="Remediation guidance")
    references: Optional[List[str]] = Field(default=None, description="Reference links")
    
    mitre_techniques: Optional[List[str]] = Field(default=None, description="MITRE ATT&CK techniques")
    tags: Optional[List[str]] = Field(default=None, description="Rule tags")
    
    @validator('id')
    def validate_id(cls, v):
        import re
        pattern = r'^[A-Z]{3,4}-[A-Z0-9]{2,4}-[0-9]{3}$'
        if not re.match(pattern, v):
            raise ValueError('Rule ID must match pattern: AWS-SG-001')
        return v
    
    @validator('version')
    def validate_version(cls, v):
        if v < 1 or v > 10:
            raise ValueError('Version must be between 1 and 10')
        return v
    
    class Config:
        use_enum_values = True

# Rule Schema JSON Schema (for validation)
RULE_SCHEMA_JSON = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["id", "title", "description", "provider", "service", "resource_type", "severity", "condition"],
    "properties": {
        "id": {"type": "string", "pattern": "^[A-Z]{3,4}-[A-Z0-9]{2,4}-[0-9]{3}$"},
        "version": {"type": "integer", "minimum": 1, "maximum": 10},
        "enabled": {"type": "boolean"},
        "title": {"type": "string", "minLength": 5, "maxLength": 100},
        "description": {"type": "string", "minLength": 10},
        "provider": {"enum": ["aws", "azure", "gcp"]},
        "service": {"type": "string"},
        "resource_type": {"enum": [
            "ec2_instance", "lambda_function", "s3_bucket", 
            "iam_user", "iam_role", "iam_policy",
            "security_group", "vpc", "subnet",
            "rds_instance"
        ]},
        "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
        "condition": {
            "type": "object",
            "required": ["field", "operator"],
            "properties": {
                "field": {"type": "string"},
                "operator": {"enum": [
                    "equals", "not_equals", "exists", "not_exists",
                    "contains", "not_contains", "greater_than", "less_than",
                    "in", "not_in", "regex", "network_exposure"
                ]},
                "value": {"type": ["string", "number", "boolean", "array", "object"]}
            }
        },
        "remediation": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "steps": {"type": "array", "items": {"type": "string"}},
                "references": {"type": "array", "items": {"type": "string"}}
            }
        },
        "references": {"type": "array", "items": {"type": "string"}},
        "mitre_techniques": {"type": "array", "items": {"type": "string"}},
        "tags": {"type": "array", "items": {"type": "string"}}
    }
}
