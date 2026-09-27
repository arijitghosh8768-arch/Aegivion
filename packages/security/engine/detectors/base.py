from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel
from app.models.security_event import SecurityEvent

class DetectionEvidence(BaseModel):
    event_id: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    timestamp: datetime

class DetectionResult(BaseModel):
    detector_name: str
    attack_type: str
    is_suspicious: bool
    confidence_score: float  # 0.0 to 1.0
    actor_id: Optional[str] = None
    affected_resources: List[str] = []
    evidence: List[DetectionEvidence] = []
    metadata: Dict[str, Any] = {}
    timestamp: datetime = datetime.utcnow()

class BaseDetector:
    """
    Common interface for all independent attack detectors.
    """
    
    @property
    def name(self) -> str:
        raise NotImplementedError
        
    @property
    def attack_type(self) -> str:
        raise NotImplementedError

    def evaluate(self, event: SecurityEvent, twin_context: Dict[str, Any]) -> DetectionResult:
        """
        Evaluate a single event against historical context.
        """
        raise NotImplementedError
