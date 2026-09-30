from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field
from enum import Enum

from security.engine.detectors.base import DetectionResult
from security.engine.dynamic_attack_path import DynamicAttackPathRiskResult
from security.engine.temporal_attack_progression import TemporalProgressionResult
from security.engine.unified_attack_activation import UnifiedAttackActivationResult

class AttackStage(str, Enum):
    UNKNOWN = "UNKNOWN"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_COLLECTION = "DATA_COLLECTION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    DESTRUCTION = "DESTRUCTION"
    RECOVERY_SABOTAGE = "RECOVERY_SABOTAGE"

class PredictionCandidate(BaseModel):
    stage: AttackStage
    score: float
    confidence: str
    evidence: List[str]

class NextStagePredictionResult(BaseModel):
    prediction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str
    current_stage: AttackStage
    predictions: List[PredictionCandidate]
    primary_prediction: Optional[AttackStage] = None
    prediction_horizon_minutes: int = 60
    uncertainty: str
    state: str
    observed_evidence: List[str] = []
    inferred_factors: List[str] = []
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

TRANSITIONS = {
    AttackStage.INITIAL_ACCESS: [
        AttackStage.CREDENTIAL_COMPROMISE
    ],
    AttackStage.CREDENTIAL_COMPROMISE: [
        AttackStage.PRIVILEGE_ESCALATION,
        AttackStage.RESOURCE_ACCESS,
    ],
    AttackStage.PRIVILEGE_ESCALATION: [
        AttackStage.RESOURCE_ACCESS,
        AttackStage.LATERAL_MOVEMENT,
        AttackStage.DEFENSE_EVASION,
    ],
    AttackStage.RESOURCE_ACCESS: [
        AttackStage.DATA_COLLECTION,
        AttackStage.DATA_EXFILTRATION,
        AttackStage.LATERAL_MOVEMENT,
    ],
    AttackStage.DATA_COLLECTION: [
        AttackStage.DATA_EXFILTRATION,
    ],
    AttackStage.DATA_EXFILTRATION: [
        AttackStage.DESTRUCTION,
    ],
    AttackStage.DESTRUCTION: [
        AttackStage.RECOVERY_SABOTAGE,
    ],
}

class NextStagePredictionEngine:
    """
    Read-only engine that estimates the most plausible next attack stage based on observed evidence.
    """
    
    def evaluate(self,
                 organization_id: str,
                 detection_result: Optional[DetectionResult] = None,
                 activation_result: Optional[UnifiedAttackActivationResult] = None,
                 path_result: Optional[DynamicAttackPathRiskResult] = None,
                 temporal_result: Optional[TemporalProgressionResult] = None,
                 explicit_current_stage: Optional[AttackStage] = None) -> NextStagePredictionResult:
        
        # 1. Tenant validation
        if detection_result:
            det_org = getattr(detection_result, "organization_id", None) or detection_result.metadata.get("organization_id")
            if det_org and det_org != organization_id:
                raise ValueError("Cross-tenant DetectionResult")
        if activation_result and activation_result.organization_id != organization_id:
            raise ValueError("Cross-tenant UnifiedAttackActivationResult")
        if path_result and path_result.organization_id != organization_id:
            raise ValueError("Cross-tenant DynamicAttackPathRiskResult")
        if temporal_result and temporal_result.organization_id != organization_id:
            raise ValueError("Cross-tenant TemporalProgressionResult")
            
        inferred = []
        observed = []
        
        # 2. Determine current stage
        current_stage = self._determine_current_stage(
            explicit_current_stage, temporal_result, detection_result
        )
        inferred.append(f"Current stage set to {current_stage.value}")
        
        if current_stage == AttackStage.UNKNOWN:
            return self._build_result(organization_id, current_stage, [], "INSUFFICIENT_EVIDENCE", "HIGH", observed, inferred)
            
        candidates = TRANSITIONS.get(current_stage, [])
        if not candidates:
            return self._build_result(organization_id, current_stage, [], "NO_SUPPORTED_TRANSITION", "HIGH", observed, inferred)
            
        # 3. Calculate scores for candidates
        predictions = []
        for cand in candidates:
            score, cand_evidence = self._calculate_score(cand, detection_result, path_result, temporal_result)
            
            if score >= 0.75:
                conf = "HIGH"
            elif score >= 0.50:
                conf = "MEDIUM"
            elif score >= 0.25:
                conf = "LOW"
            else:
                conf = "INSUFFICIENT_EVIDENCE"
                
            predictions.append(PredictionCandidate(
                stage=cand,
                score=round(score, 3),
                confidence=conf,
                evidence=cand_evidence
            ))
            
        # Sort by score desc
        predictions.sort(key=lambda x: x.score, reverse=True)
        
        # 4. Determine state and uncertainty
        if not predictions or predictions[0].score < 0.25:
            state = "INSUFFICIENT_EVIDENCE"
            primary = None
            uncertainty = "HIGH"
        else:
            primary = predictions[0].stage
            state = "PREDICTED"
            uncertainty = "LOW"
            
            # Check for ambiguity
            if len(predictions) > 1:
                diff = predictions[0].score - predictions[1].score
                if diff < 0.1:
                    state = "AMBIGUOUS"
                    uncertainty = "MEDIUM"
                elif diff < 0.2:
                    uncertainty = "MEDIUM"
                    
            if not path_result or not temporal_result:
                uncertainty = "HIGH"
                
        return self._build_result(organization_id, current_stage, predictions, state, uncertainty, observed, inferred, primary)
        
    def _determine_current_stage(self, explicit, temp_res, det_res) -> AttackStage:
        if explicit:
            return explicit
            
        if det_res:
            atype = det_res.attack_type.upper()
            if "CREDENTIAL" in atype or "LOGIN" in atype:
                return AttackStage.CREDENTIAL_COMPROMISE
            if "PRIVILEGE" in atype:
                return AttackStage.PRIVILEGE_ESCALATION
            if "EXFILTRATION" in atype:
                return AttackStage.DATA_COLLECTION
            if "DESTRUCTION" in atype or "RANSOMWARE" in atype:
                return AttackStage.DESTRUCTION
                
        return AttackStage.UNKNOWN
        
    def _calculate_score(self, cand: AttackStage, det, path, temp) -> tuple[float, List[str]]:
        # Weights
        w_prior = 0.15
        w_temp = 0.25
        w_actor = 0.15
        w_res = 0.15
        w_path = 0.20
        w_det = 0.10
        
        score = w_prior * 1.0  # Basic transition prior
        evidence = ["OBSERVED: Valid topological transition from current stage"]
        
        if temp:
            # Temporal gives support based on its own score
            ts = temp.progression_score
            score += w_temp * ts
            evidence.append(f"INFERRED: Temporal progression score {ts}")
            
            # Actor Continuity
            has_actor = getattr(temp, "actor_id", None) is not None
            if has_actor:
                score += w_actor * 1.0
                evidence.append("OBSERVED: Actor continuity confirmed in temporal data")
        else:
            evidence.append("UNKNOWN: Temporal evidence missing")
            
        if path:
            ps = path.risk_score
            score += w_path * ps
            evidence.append(f"INFERRED: Path risk support score {ps}")
            
            has_res = len(getattr(path, "path_nodes", [])) > 0
            if has_res:
                score += w_res * 1.0
                evidence.append("OBSERVED: Resource continuity via attack path")
        else:
            evidence.append("UNKNOWN: Path risk evidence missing")
            
        if det:
            ds = det.confidence_score
            score += w_det * ds
            evidence.append(f"INFERRED: Detector confidence support {ds}")
        else:
            evidence.append("UNKNOWN: Detection evidence missing")
            
        return score, evidence

    def _build_result(self, org, curr, preds, state, uncert, obs, inf, primary=None):
        return NextStagePredictionResult(
            organization_id=org,
            current_stage=curr,
            predictions=preds,
            primary_prediction=primary,
            prediction_horizon_minutes=60,
            uncertainty=uncert,
            state=state,
            observed_evidence=obs,
            inferred_factors=inf
        )
