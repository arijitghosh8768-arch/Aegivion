from typing import Dict, Any, List
from datetime import datetime
import uuid

from security.models.response_candidate_schema import ResponseCandidateSchema
from security.models.response_policy_schema import GateDecision
from packages.security.engine.risk_engine_v2 import RiskEngineV2

class CloudActionAdapterMock:
    """Mock cloud adapter for Step 1I testing purposes."""
    
    @staticmethod
    def execute(action: str, target: str) -> Dict[str, Any]:
        """Simulates cloud API execution (e.g. boto3 calls)"""
        if action == "revoke_identity_session":
            return {"status": "success", "provider_response": {"http_code": 200, "message": "Sessions revoked"}}
        elif action == "isolate_network":
            return {"status": "success", "provider_response": {"http_code": 200, "message": "Security group detached"}}
        return {"status": "failed", "provider_response": {"http_code": 400, "message": "Unknown action"}}
        
    @staticmethod
    def get_state(target: str) -> Dict[str, Any]:
        """Simulates pulling cloud state for a target"""
        return {"target": target, "active_sessions": 0, "attached_sgs": []}


class SafeResponseExecutor:
    """
    Executes allowlisted actions and verifies the resulting threat mitigation.
    Enforces the Action Gate boundary.
    """
    
    @staticmethod
    def execute_and_verify(
        candidate: ResponseCandidateSchema, 
        gate_decision: GateDecision,
        incident_id: str,
        initial_risk_score: float,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        
        # 1. Action Gate enforcement
        if gate_decision != GateDecision.ALLOW:
            return {
                "execution_status": "rejected",
                "reason": f"Gate decision was {gate_decision.value}. Only ALLOW is permitted to execute.",
                "verification": "failed"
            }
            
        # 2. Record Before State
        before_state = {
            "action": candidate.action,
            "target": candidate.target,
            "provider": "aws", # Mocked default
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "cloud_state": CloudActionAdapterMock.get_state(candidate.target)
        }
        
        # 3. Execute
        try:
            execution_result = CloudActionAdapterMock.execute(candidate.action, candidate.target)
        except Exception as e:
            execution_result = {"status": "failed", "error": str(e)}
            
        # 4. Record After State
        after_state = {
            "cloud_state": CloudActionAdapterMock.get_state(candidate.target),
            "execution_status": execution_result.get("status"),
            "provider_response": execution_result.get("provider_response")
        }
        
        # 5. Verification (Simulation)
        # Normally this would re-run detection and RiskEngineV2. 
        # Here we simulate the logic based on execution success.
        
        if execution_result.get("status") != "success":
            verification = "failed"
            new_risk_score = initial_risk_score
        else:
            # Simulate a risk reduction check
            # For testing, we mock that a successful revoke drops the risk score by 40 points
            if candidate.action == "revoke_identity_session":
                new_risk_score = max(0, initial_risk_score - 40)
            else:
                new_risk_score = initial_risk_score - 10
                
            if new_risk_score < initial_risk_score:
                verification = "threat reduced"
            elif new_risk_score == initial_risk_score:
                verification = "threat unchanged"
            else:
                verification = "threat increased"
                
        return {
            "execution_status": execution_result.get("status"),
            "before_state": before_state,
            "after_state": after_state,
            "verification": verification,
            "initial_risk": initial_risk_score,
            "new_risk": new_risk_score
        }
