from typing import List, Dict, Any
from security.models.attack_prediction_schema import AttackPredictionSchema
from security.models.attack_activation_schema import AttackActivationSchema
from security.models.security_correlation_schema import SecurityCorrelationSchema

class AttackPredictionEngine:
    """
    Engine to predict plausible next stages of an active attack based on activation and correlation evidence.
    """
    
    @staticmethod
    def predict_next_stage(activation: AttackActivationSchema, storyline: SecurityCorrelationSchema) -> List[AttackPredictionSchema]:
        predictions = []
        
        # We only predict if there is an active attack
        if activation.activation_score < 10.0:
            return predictions
            
        identity = storyline.actors[0] if storyline.actors else "unknown"
        
        for attack_type in activation.attack_types:
            if attack_type == "credential_compromise":
                predictions.append(AttackPredictionSchema(
                    current_attack_type=attack_type,
                    next_stage="privilege_escalation_or_lateral_movement",
                    confidence=0.75,
                    supporting_evidence=["Credential compromise detected in activation score"],
                    potential_targets=storyline.affected_assets,
                    affected_identity=identity,
                    reason="Compromised credentials are typically used immediately for escalation or to access other internal resources."
                ))
            elif attack_type == "data_exfiltration":
                predictions.append(AttackPredictionSchema(
                    current_attack_type=attack_type,
                    next_stage="ransomware_or_destruction",
                    confidence=0.60,
                    supporting_evidence=["Data exfiltration signals detected"],
                    potential_targets=storyline.affected_assets,
                    affected_identity=identity,
                    reason="Exfiltration is often followed by ransomware encryption or data destruction to cover tracks or extort."
                ))
                
        return predictions
