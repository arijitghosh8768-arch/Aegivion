from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field
from enum import Enum

from security.engine.detectors.base import DetectionResult
from security.engine.dynamic_attack_path import DynamicAttackPathRiskResult
from security.engine.temporal_attack_progression import TemporalProgressionResult

class ActivationState(str, Enum):
    INACTIVE = "INACTIVE"
    POTENTIAL = "POTENTIAL"
    ACTIVATING = "ACTIVATING"
    ACTIVE = "ACTIVE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

class UnifiedEvidence(BaseModel):
    factor: str
    source_event_ids: List[str] = []
    contribution: float = 0.0
    classification: str  # "OBSERVED", "INFERRED", "UNKNOWN"
    description: str = ""

class UnifiedAttackActivationResult(BaseModel):
    activation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str
    detector_confidence: Optional[float]
    path_risk: Optional[float]
    temporal_progression_score: Optional[float]
    activation_score: float
    state: ActivationState
    evidence_trace: List[UnifiedEvidence] = []
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    algorithm_version: str = "1.0"


class UnifiedAttackActivationEngine:
    """
    Unifies Detector Confidence, Dynamic Path Risk, and Temporal Progression
    into a single Activation Score indicating whether a viable path is actively
    being exploited.
    """
    
    def evaluate(self, 
                 organization_id: str,
                 detection_result: Optional[DetectionResult] = None,
                 path_risk_result: Optional[DynamicAttackPathRiskResult] = None,
                 temporal_result: Optional[TemporalProgressionResult] = None) -> UnifiedAttackActivationResult:
        
        # 1. Tenant isolation validation
        if detection_result:
            det_org = getattr(detection_result, "organization_id", None) or detection_result.metadata.get("organization_id")
            if det_org and det_org != organization_id:
                raise ValueError("Cross-tenant DetectionResult")
                
        if path_risk_result and path_risk_result.organization_id != organization_id:
            raise ValueError("Cross-tenant PathRiskResult")
            
        if temporal_result and temporal_result.organization_id != organization_id:
            raise ValueError("Cross-tenant TemporalProgressionResult")
            
        # 2. Extract underlying scores
        det_score = detection_result.confidence_score if detection_result else None
        path_score = path_risk_result.risk_score if path_risk_result else None
        temp_score = temporal_result.progression_score if temporal_result else None
        
        evidence = []
        
        if det_score is not None:
            evidence.append(UnifiedEvidence(
                factor="DETECTOR_CONFIDENCE",
                contribution=det_score,
                classification="INFERRED",
                description=f"Detector reported confidence of {det_score}"
            ))
            
        if path_score is not None:
            evidence.append(UnifiedEvidence(
                factor="PATH_RISK",
                contribution=path_score,
                classification="INFERRED",
                description=f"Dynamic path risk scored at {path_score}"
            ))
            
        if temp_score is not None:
            evidence.append(UnifiedEvidence(
                factor="TEMPORAL_PROGRESSION",
                contribution=temp_score,
                classification="INFERRED",
                description=f"Temporal progression scored at {temp_score}"
            ))
            
        # 3. Calculate Unified Score
        score = 0.0
        
        if det_score is None and path_score is None and temp_score is None:
            return self._build_result(organization_id, None, None, None, 0.0, ActivationState.INSUFFICIENT_EVIDENCE, [])
            
        # Weights definition
        # If temporal is missing, detector and path split 50/50.
        # If temporal exists, detector 40, path 40, temporal 20.
        
        # Path Gating
        has_viable_path = path_score is not None and path_score >= 0.1
        
        if not has_viable_path:
            # If no path is provided or path risk is near zero, 
            # activation is severely gated. We cap it at POTENTIAL (0.49).
            if det_score is not None:
                score = det_score * 0.49
            elif temp_score is not None:
                score = temp_score * 0.49
            
            evidence.append(UnifiedEvidence(
                factor="PATH_GATING",
                classification="INFERRED",
                description="Score capped at POTENTIAL due to lack of viable path evidence."
            ))
            
        else:
            # We have a viable path.
            if det_score is None:
                det_score_eff = 0.0
            else:
                det_score_eff = det_score
                
            if temp_score is None:
                # Detector and Path only
                score = (det_score_eff * 0.5) + (path_score * 0.5)
            else:
                # All three
                score = (det_score_eff * 0.4) + (path_score * 0.4) + (temp_score * 0.2)

        # Temporal Gating
        if temp_score is None and score >= 0.80:
            score = 0.79
            evidence.append(UnifiedEvidence(
                factor="TEMPORAL_GATING",
                classification="INFERRED",
                description="Score capped at ACTIVATING due to missing temporal evidence."
            ))
            
        # Ensure score stays in bounds
        score = min(1.0, max(0.0, score))
        
        # 4. State classification
        if score >= 0.80:
            state = ActivationState.ACTIVE
        elif score >= 0.50:
            state = ActivationState.ACTIVATING
        elif score >= 0.25:
            state = ActivationState.POTENTIAL
        else:
            state = ActivationState.INACTIVE
            
        # Hard override for missing evidence
        if det_score is None and path_score is None:
            # Only temporal
            if state in [ActivationState.ACTIVE, ActivationState.ACTIVATING]:
                state = ActivationState.POTENTIAL
        
        return self._build_result(
            org_id=organization_id,
            det_score=det_score,
            path_score=path_score,
            temp_score=temp_score,
            final_score=score,
            state=state,
            evidence=evidence
        )
        
    def _build_result(self, org_id, det_score, path_score, temp_score, final_score, state, evidence):
        return UnifiedAttackActivationResult(
            organization_id=org_id,
            detector_confidence=det_score,
            path_risk=path_score,
            temporal_progression_score=temp_score,
            activation_score=round(final_score, 3),
            state=state,
            evidence_trace=evidence
        )
