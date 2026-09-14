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

class Asset(BaseModel):
    """
    Intelligence: Rich asset context with environment, exposure, and classification markers.
    """
    asset_id: str
    provider: str
    type: str
    configuration: dict = Field(default_factory=dict)
    
    # New Context Fields
    internet_exposed: bool = False
    environment: str = Field("dev", description="prod, staging, dev")
    data_classification: str = Field("internal", description="public, internal, confidential, restricted")
    
    @property
    def importance_score(self) -> float:
        """
        Computes a weighted importance score based on environment, data classification, and exposure.
        - Environment: prod (1.0), staging (0.5), dev (0.2)
        - Data: restricted (1.0), confidential (0.8), internal (0.3), public (0.1)
        - Exposure: Exposed multiplier (1.5)
        """
        env_weights = {"prod": 1.0, "staging": 0.5, "dev": 0.2}
        data_weights = {"restricted": 1.0, "confidential": 0.8, "internal": 0.3, "public": 0.1}
        
        base = env_weights.get(self.environment.lower(), 0.2) + data_weights.get(self.data_classification.lower(), 0.1)
        multiplier = 1.5 if self.internet_exposed else 1.0
        return min(base * multiplier, 1.0) # Normalize to 1.0

