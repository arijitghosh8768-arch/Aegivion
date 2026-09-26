from pydantic import BaseModel, Field
from typing import List, Dict, Any

class AttackSimulationSchema(BaseModel):
    """
    Signal representing what could potentially happen if an identity or path remains available.
    Calculated via graph analysis without modifying cloud resources.
    """
    identity: str = Field(..., description="The suspicious identity or starting point")
    reachable_assets: int = Field(default=0, description="Total number of assets reachable via permissions/network")
    sensitive_assets: int = Field(default=0, description="Subset of reachable assets marked as sensitive/critical")
    blast_radius: str = Field(default="unknown", description="Qualitative blast radius (low, medium, high, critical)")
    paths: List[Dict[str, Any]] = Field(default_factory=list, description="Summary of potential attack paths")
