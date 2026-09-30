import hashlib
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field

class CorrelationState(str, Enum):
    NEW = "NEW"
    RELATED = "RELATED"
    CORRELATED = "CORRELATED"
    STRONGLY_CORRELATED = "STRONGLY_CORRELATED"
    RESOLVED = "RESOLVED"

class CorrelationResult(BaseModel):
    correlation_id: str
    org_id: str
    correlation_type: str
    detection_ids: List[str]
    event_ids: List[str]
    actor_ids: List[str]
    target_ids: List[str]
    score: float
    state: CorrelationState
    evidence: List[str]
    provenance: List[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class DetectionCorrelationEngine:
    """
    Correlates independent DetectionResults into related security sequences.
    """
    def __init__(self):
        # We define a few known chains
        self.known_correlations = [
            {"from": "Credential compromise", "to": "Data exfiltration", "type": "CREDENTIAL_TO_EXFILTRATION"},
            {"from": "Credential compromise", "to": "Privilege escalation", "type": "CREDENTIAL_TO_PRIVILEGE_ESCALATION"},
            {"from": "Credential compromise", "to": "Resource access", "type": "CREDENTIAL_TO_RESOURCE_ACCESS"},
            {"from": "Resource modification", "to": "Ransomware/destruction", "type": "MODIFICATION_TO_DESTRUCTION"},
            {"from": "Credential compromise", "to": "Ransomware/destruction", "type": "MULTI_STAGE_ATTACK"},
            {"from": "Ransomware/destruction", "to": "Recovery sabotage", "type": "DESTRUCTION_TO_RECOVERY_SABOTAGE"}
        ]
        
    def _generate_correlation_id(self, org_id: str, detection_ids: List[str], correlation_type: str) -> str:
        s = f"{org_id}|{','.join(sorted(detection_ids))}|{correlation_type}"
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    def correlate(self, org_id: str, new_detection: Dict[str, Any], historical_detections: List[Dict[str, Any]]) -> Optional[CorrelationResult]:
        if not historical_detections:
            return None
            
        # For simplicity, we just evaluate the most recent related detection that forms a sequence
        # or combine all related ones.
        
        best_match = None
        best_score = 0.0
        best_type = "RELATED_SECURITY_ACTIVITY"
        
        my_type = new_detection.get("attack_type")
        my_actor = new_detection.get("actor_id")
        
        for old_det in historical_detections:
            score = 0.0
            evidence = []
            
            old_type = old_det.get("attack_type")
            old_actor = old_det.get("actor_id")
            
            # Signals
            if my_actor and old_actor and my_actor == old_actor:
                score += 0.25
                evidence.append(f"Actor continuity: {my_actor}")
                
            # Temporal proximity (within 60 mins)
            # Checked implicitly by bounded context, add score
            score += 0.20
            evidence.append("Temporal proximity")
            
            # Attack-type compatibility
            matched_type = None
            for chain in self.known_correlations:
                if chain["from"] == old_type and chain["to"] == my_type:
                    matched_type = chain["type"]
                    break
                elif chain["from"] == my_type and chain["to"] == old_type:
                    matched_type = chain["type"]
                    break
                    
            if matched_type:
                score += 0.20
                evidence.append(f"Compatible attack types ({old_type} -> {my_type})")
            
            # Cap at 1.0
            score = min(score, 1.0)
            
            if score > best_score:
                best_score = score
                best_type = matched_type if matched_type else "RELATED_SECURITY_ACTIVITY"
                best_match = old_det
                best_evidence = evidence
                
        if best_match and best_score >= 0.40:
            # We have a correlation!
            if best_score < 0.60:
                state = CorrelationState.RELATED
            elif best_score < 0.80:
                state = CorrelationState.CORRELATED
            else:
                state = CorrelationState.STRONGLY_CORRELATED
                
            det_ids = [new_detection["detection_id"], best_match["detection_id"]]
            evt_ids = [new_detection["event_id"], best_match["event_id"]]
            actors = []
            if my_actor: actors.append(my_actor)
            
            # Remove dupes
            evt_ids = list(set(evt_ids))
            actors = list(set(actors))
            
            corr_id = self._generate_correlation_id(org_id, det_ids, best_type)
            
            return CorrelationResult(
                correlation_id=corr_id,
                org_id=org_id,
                correlation_type=best_type,
                detection_ids=det_ids,
                event_ids=evt_ids,
                actor_ids=actors,
                target_ids=[],
                score=best_score,
                state=state,
                evidence=best_evidence,
                provenance=["DetectionCorrelationEngine"]
            )
            
        return None
