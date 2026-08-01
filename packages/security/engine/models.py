from pydantic import BaseModel, Field
from typing import Optional

class Rule(BaseModel):
    id: str = Field(..., description="Unique rule identifier (e.g. AWS-NET-001)")
    version: int = Field(1, description="Rule version number")
    enabled: bool = True
    title: str = Field(..., description="Short, descriptive title of the rule")
    provider: str = Field(..., description="Cloud provider (e.g. aws, azure, gcp)")
    resource_type: str = Field(..., description="Resource type the rule applies to")
    severity: str = Field(..., description="Severity of violations (critical, high, medium, low, info)")
    description: str = Field(..., description="Detailed description of the check")
