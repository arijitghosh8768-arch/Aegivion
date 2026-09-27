from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field

from security.engine.detectors.base import DetectionResult

class AttackActivationResult(BaseModel):
    activation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str
    attack_type: str
    detection_reference: str
    activation_score: float
    activation_state: str  # INACTIVE, POTENTIAL, ACTIVATING, ACTIVE, INSUFFICIENT_EVIDENCE
    actor_id: Optional[str] = None
    entry_asset_id: Optional[str] = None
    target_asset_ids: List[str] = Field(default_factory=list)
    attack_path: List[str] = Field(default_factory=list)
    path_length: int = 0
    path_risk: str = "UNKNOWN"
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    temporal_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contributing_factors: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: float
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detector_version: str = "1.0"

class AttackActivationEngine:
    """
    Evaluates whether an existing DetectionResult corresponds to a viable attack path 
    that is actively being traversed.
    """
    
    # 30-minute window for temporal progression evaluation
    ATTACK_ACTIVATION_WINDOW_MINUTES = 30
    
    def evaluate(self, detection: DetectionResult, twin_context: Dict[str, Any], event_history: List[Any] = None) -> AttackActivationResult:
        if event_history is None:
            event_history = []
            
        organization_id = twin_context.get("organization_id", "unknown")
        
        # Initialize evidence and factors
        contributing_factors = []
        activation_score = 0.0
        
        # 1. Detection Evidence
        if detection.is_suspicious:
            activation_score += 0.3
            contributing_factors.append({
                "factor": "DETECTION_EVIDENCE",
                "source": "detector",
                "evidence": f"Detector {detection.detector_name} flagged suspicious activity with confidence {detection.confidence_score}",
                "classification": "OBSERVED"
            })
        else:
            return self._build_result(detection, organization_id, 0.0, "INACTIVE", contributing_factors)

        # 2. Identity Relationship & Privilege Risk
        actor_id = detection.actor_id
        is_privileged = False
        if actor_id and "actor_roles" in twin_context:
            roles = twin_context["actor_roles"]
            if any("admin" in role.lower() or "owner" in role.lower() or "write" in role.lower() for role in roles):
                is_privileged = True
                activation_score += 0.2
                contributing_factors.append({
                    "factor": "PRIVILEGED_ACCESS",
                    "source": "identity-role relationship",
                    "evidence": f"Actor has privileged roles: {roles}",
                    "classification": "OBSERVED"
                })
        elif actor_id is None:
            # If there's a detection but we can't even trace identity, we might lack sufficient evidence to map a path
            contributing_factors.append({
                "factor": "MISSING_IDENTITY",
                "source": "twin_context",
                "evidence": "Actor ID is missing",
                "classification": "UNKNOWN"
            })
            
        # 3. Resource Reachability (Path Completeness)
        # We simulate checking if a path exists from actor to target in the twin context.
        path_completeness = "NO_PATH"
        attack_path = []
        targets = detection.affected_resources
        valid_path_exists = twin_context.get("valid_path_exists", False)
        
        if valid_path_exists and actor_id and targets:
            path_completeness = "VALID_PATH"
            activation_score += 0.3
            attack_path = [actor_id, "intermediate-role", targets[0]]
            contributing_factors.append({
                "factor": "RESOURCE_REACHABILITY",
                "source": "digital_twin_graph",
                "evidence": f"Valid path exists from {actor_id} to {targets}",
                "classification": "INFERRED"
            })
        elif "partial_path_exists" in twin_context and twin_context["partial_path_exists"]:
            path_completeness = "PARTIAL_PATH"
            activation_score += 0.1
            
        # 4. Asset Criticality
        is_critical = False
        if targets:
            # Check if any target is in critical assets list
            critical_assets = twin_context.get("critical_assets", [])
            for target in targets:
                if target in critical_assets:
                    is_critical = True
                    break
            
            if is_critical:
                activation_score += 0.2
                contributing_factors.append({
                    "factor": "ASSET_CRITICALITY",
                    "source": "asset_metadata",
                    "evidence": f"Target {targets} is classified as critical",
                    "classification": "OBSERVED"
                })
                
        # 5. Temporal Evidence
        # Look for events in the history window that are part of the attack chain
        temporal_evidence = []
        if len(event_history) >= 2:
            recent_events = [e for e in event_history if hasattr(e, "timestamp") and e.timestamp]
            if len(recent_events) >= 2:
                # Naive mock for temporal progression
                activation_score += 0.2
                temporal_evidence = [{"event_id": e.event_id} for e in recent_events[-2:] if hasattr(e, "event_id")]
                contributing_factors.append({
                    "factor": "TEMPORAL_PROGRESSION",
                    "source_event_ids": [te["event_id"] for te in temporal_evidence],
                    "classification": "INFERRED"
                })

        # Cap score at 1.0
        activation_score = min(1.0, activation_score)
        
        # State machine
        state = "INSUFFICIENT_EVIDENCE"
        if not actor_id:
            state = "INSUFFICIENT_EVIDENCE"
        elif path_completeness == "NO_PATH" and activation_score < 0.5:
            state = "INACTIVE"
        elif path_completeness == "PARTIAL_PATH":
            state = "POTENTIAL"
        elif path_completeness == "VALID_PATH":
            if activation_score >= 0.8:
                state = "ACTIVE"
            elif activation_score >= 0.5:
                state = "ACTIVATING"
            else:
                state = "POTENTIAL"
                
        result = self._build_result(
            detection=detection,
            organization_id=organization_id,
            score=activation_score,
            state=state,
            factors=contributing_factors,
            attack_path=attack_path,
            temporal_evidence=temporal_evidence
        )
        return result

    def _build_result(self, detection: DetectionResult, organization_id: str, score: float, state: str, factors: List[Dict[str, Any]], attack_path: List[str] = None, temporal_evidence: List[Dict[str, Any]] = None) -> AttackActivationResult:
        return AttackActivationResult(
            organization_id=organization_id,
            attack_type=detection.attack_type,
            detection_reference=detection.detector_name,
            activation_score=score,
            activation_state=state,
            actor_id=detection.actor_id,
            target_asset_ids=detection.affected_resources,
            contributing_factors=factors,
            attack_path=attack_path or [],
            path_length=len(attack_path) if attack_path else 0,
            temporal_evidence=temporal_evidence or [],
            confidence=detection.confidence_score,
            detector_version=detection.metadata.get("detector_version", "1.0")
        )
