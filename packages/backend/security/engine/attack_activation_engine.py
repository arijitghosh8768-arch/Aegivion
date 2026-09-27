from typing import Dict, Any, List
from security.models.security_correlation_schema import SecurityCorrelationSchema
from security.models.attack_activation_schema import AttackActivationSchema
from security.engine.risk_engine_v2 import RiskEngineV2
from app.cloud.aws.relationships.engine import RelationshipEngine

class AttackActivationEngine:
    """
    Calculates the Attack Activation Score (0-100) from dynamic correlated events.
    Separates the "Is an attack happening?" (Activation) from "How bad is it?" (Path Risk).
    """
    
    @staticmethod
    def calculate_activation(storyline: SecurityCorrelationSchema) -> AttackActivationSchema:
        score = 0.0
        signals = {}
        
        # 1. Detector Evidence & Confidence
        base_confidence = storyline.confidence * 100
        if "credential_compromise" in storyline.attack_types:
            score += 40
            signals["credential_compromise"] = 40
        if "ransomware" in storyline.attack_types:
            score += 50
            signals["ransomware"] = 50
        if "data_exfiltration" in storyline.attack_types:
            score += 30
            signals["data_exfiltration"] = 30
            
        # 2. Temporal Sequence (Rapid succession increases score)
        if len(storyline.events) >= 3:
            score += 15
            signals["temporal_velocity"] = 15
            
        # 3. Apply base confidence multiplier
        score = min(100.0, score * storyline.confidence)
        
        return AttackActivationSchema(
            activation_score=score,
            signals=signals,
            attack_types=storyline.attack_types,
            affected_assets=storyline.affected_assets,
            affected_identities=storyline.actors,
            evidence=storyline.evidence
        )
        
    @staticmethod
    def evaluate_dynamic_path_risk(activation: AttackActivationSchema, twin_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Feeds the activation into existing attack-path/risk machinery.
        Reuses RiskEngineV2 and AWS RelationshipEngine logic conceptually.
        """
        # Note: We reuse RiskEngineV2 which expects (finding, context, correlations)
        # Here we map the dynamic activation into a pseudo-finding for the engine to evaluate static risk
        risk_engine = RiskEngineV2()
        
        pseudo_finding = {
            "severity": "critical" if activation.activation_score > 75 else "high",
            "rule_id": "dynamic-attack-activation"
        }
        
        # Assuming twin_context contains context similar to what RiskEngineV2 expects
        context = twin_context or {}
        
        # Calculate Path Risk utilizing existing machinery
        risk_score = risk_engine.calculate_risk(pseudo_finding, context, correlations=[])
        
        # Identify attack paths utilizing existing relationships engine logic
        # For full implementation, we'd invoke app.cloud.aws.relationships.engine.RelationshipEngine.get_attack_paths
        
        return {
            "path_risk_score": risk_score.score,
            "path_risk_level": risk_score.level.value,
            "risk_factors": [f.to_dict() for f in risk_score.factors]
        }
