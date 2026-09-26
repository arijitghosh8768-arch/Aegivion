from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

class SecurityCorrelationSchema(BaseModel):
    """
    Contract for correlating multiple detector signals into a single Incident storyline.
    Designed to map seamlessly into the existing app.models.incident.Incident.
    """
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str
    
    # These map cleanly to Incident's 'evidence' dict if not natively supported
    attack_types: List[str] = Field(default_factory=list)
    actors: List[str] = Field(default_factory=list)
    events: List[str] = Field(default_factory=list)  # event IDs
    
    # Natively supported by Incident
    confidence: float = 0.8
    severity: str = "medium"
    affected_assets: List[str] = Field(default_factory=list)  # Maps to asset_ids
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    correlation_reason: str = "Correlated based on temporal and actor overlap."
    
    def to_incident_dict(self) -> Dict[str, Any]:
        """Convert this correlation output into a dictionary suitable for the Incident model."""
        return {
            "id": self.incident_id,
            "organization_id": self.organization_id,
            "title": f"Active Attack Storyline: {', '.join(self.attack_types).title()}",
            "description": self.correlation_reason,
            "severity": self.severity,
            "confidence": self.confidence,
            "asset_ids": self.affected_assets,
            "timeline": self.timeline,
            "evidence": {
                **self.evidence,
                "attack_types": self.attack_types,
                "actors": self.actors,
                "events": self.events
            },
            "correlation_fingerprint": "-".join(sorted(self.actors + self.affected_assets))
        }
