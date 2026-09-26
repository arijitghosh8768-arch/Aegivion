import unittest
import os
import sys

sys.path.insert(0, os.path.abspath("packages/backend"))
sys.path.insert(0, os.path.abspath("."))

from security.models.response_candidate_schema import ResponseCandidateSchema
from security.models.response_policy_schema import ResponsePolicySchema, GateDecision, AllowedActionSchema
from security.engine.response_action_gate import ResponseActionGate
from security.engine.safe_response_executor import SafeResponseExecutor
from security.models.security_replay_schema import SecurityReplaySchema
from security.engine.security_replay_engine import SecurityReplayEngine


class TestPart2V3ResponseIntegration(unittest.TestCase):
    def setUp(self):
        self.incident_id = "inc-test-v3"
        self.target_arn = "arn:aws:iam::aws-test-001:user/compromised_dev"
        self.initial_risk = 85.0
        self.context = {"incident_id": self.incident_id}
        
        self.candidate = ResponseCandidateSchema(
            action="revoke_identity_session",
            target=self.target_arn,
            attack_path_reduction=0.8,
            business_impact="low",
            blast_radius="small",
            reversibility=True,
            confidence=0.9,
            reason="High risk identity compromise detected",
            approval_required="REQUIRES_APPROVAL"
        )

    def test_gate_block_and_executor_rejects(self):
        # Policy explicitly does not allow this action
        policy = ResponsePolicySchema(allowlist=[AllowedActionSchema(action_type="isolate_network")])
        
        # 1. Gate Evaluation
        gate_decision = ResponseActionGate.evaluate(self.candidate, policy)
        self.assertEqual(gate_decision, GateDecision.BLOCK)
        
        # 2. Execution Evaluation
        result = SafeResponseExecutor.execute_and_verify(
            candidate=self.candidate,
            gate_decision=gate_decision,
            incident_id=self.incident_id,
            initial_risk_score=self.initial_risk,
            context=self.context
        )
        
        self.assertEqual(result["execution_status"], "rejected")
        self.assertEqual(result["verification"], "failed")

    def test_gate_require_approval_and_executor_rejects(self):
        # Policy allows the action, but no human approval has been given yet
        policy = ResponsePolicySchema(allowlist=[AllowedActionSchema(action_type="revoke_identity_session", requires_approval=True)])
        
        # 1. Gate Evaluation (No approval state provided)
        gate_decision = ResponseActionGate.evaluate(self.candidate, policy)
        self.assertEqual(gate_decision, GateDecision.REQUIRE_APPROVAL)
        
        # 2. Execution Evaluation
        result = SafeResponseExecutor.execute_and_verify(
            candidate=self.candidate,
            gate_decision=gate_decision,
            incident_id=self.incident_id,
            initial_risk_score=self.initial_risk,
            context=self.context
        )
        
        self.assertEqual(result["execution_status"], "rejected")
        self.assertEqual(result["verification"], "failed")

    def test_gate_allow_and_executor_success(self):
        # Policy allows the action, and human approval was granted
        policy = ResponsePolicySchema(allowlist=[AllowedActionSchema(action_type="revoke_identity_session", requires_approval=True)])
        
        # 1. Gate Evaluation (Approval provided)
        gate_decision = ResponseActionGate.evaluate(
            self.candidate, 
            policy, 
            approval_state="APPROVED"
        )
        self.assertEqual(gate_decision, GateDecision.ALLOW)
        
        # 2. Execution Evaluation
        result = SafeResponseExecutor.execute_and_verify(
            candidate=self.candidate,
            gate_decision=gate_decision,
            incident_id=self.incident_id,
            initial_risk_score=self.initial_risk,
            context=self.context
        )
        
        # It should mock the API call and succeed, returning risk reduction
        self.assertEqual(result["execution_status"], "success")
        self.assertEqual(result["verification"], "threat reduced")
        self.assertLess(result["new_risk"], self.initial_risk)
        self.assertEqual(result["new_risk"], 45.0)  # Initial 85.0 - 40 points
        
        # Check cloud before and after state capture
        self.assertIn("before_state", result)
        self.assertIn("after_state", result)

    def test_security_replay_engine_trace(self):
        # Ensure the whole flow can be recorded properly
        policy = ResponsePolicySchema(allowlist=[AllowedActionSchema(action_type="revoke_identity_session")])
        gate_decision = ResponseActionGate.evaluate(self.candidate, policy, approval_state="APPROVED")
        
        result = SafeResponseExecutor.execute_and_verify(
            candidate=self.candidate,
            gate_decision=gate_decision,
            incident_id=self.incident_id,
            initial_risk_score=self.initial_risk,
            context=self.context
        )
        
        replay = SecurityReplaySchema(
            trace_id="trc-12345",
            incident_id=self.incident_id,
            events=[{"event": "1"}],
            safety_decision=gate_decision.value,
            response_candidates=[self.candidate.model_dump() if hasattr(self.candidate, "model_dump") else self.candidate.dict()],
            execution_result=result
        )
        
        trace_id = SecurityReplayEngine.record_decision_trace(replay)
        self.assertIsNotNone(trace_id)
        
        # Fetch the replay
        reconstructed = SecurityReplayEngine.replay_incident(trace_id)
        
        self.assertEqual(reconstructed["incident_id"], self.incident_id)
        self.assertEqual(reconstructed["safety_decision"], "ALLOW")
        self.assertEqual(reconstructed["execution_result"]["verification"], "threat reduced")


if __name__ == "__main__":
    unittest.main()
