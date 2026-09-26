import unittest
import os
import sys

sys.path.insert(0, os.path.abspath("packages/backend"))
sys.path.insert(0, os.path.abspath("."))

from security.models.response_candidate_schema import ResponseCandidateSchema
from security.models.response_policy_schema import ResponsePolicySchema, GateDecision, AllowedActionSchema
from security.engine.response_action_gate import ResponseActionGate
from security.engine.safe_response_executor import SafeResponseExecutor


class TestPart2V4FailurePaths(unittest.TestCase):
    def setUp(self):
        self.incident_id = "inc-test-v4"
        self.target_arn = "arn:aws:iam::aws-test-001:user/compromised_dev"
        self.context = {"incident_id": self.incident_id}

    def test_execution_failure_returns_verification_failed(self):
        # 1. Action Gate allows an invalid action to test executor failure handling
        candidate = ResponseCandidateSchema(
            action="invalid_unsupported_action",
            target=self.target_arn,
            attack_path_reduction=0.8,
            business_impact="low",
            blast_radius="small",
            reversibility=True,
            confidence=0.9,
            reason="Testing failure paths",
            approval_required="REQUIRES_APPROVAL"
        )
        
        policy = ResponsePolicySchema(allowlist=[AllowedActionSchema(action_type="invalid_unsupported_action", requires_approval=True)])
        gate_decision = ResponseActionGate.evaluate(candidate, policy, approval_state="APPROVED")
        
        # 2. Execution Evaluation
        result = SafeResponseExecutor.execute_and_verify(
            candidate=candidate,
            gate_decision=gate_decision,
            incident_id=self.incident_id,
            initial_risk_score=85.0,
            context=self.context
        )
        
        # CloudActionAdapterMock will return "failed" because the action is unknown
        self.assertEqual(result["execution_status"], "failed")
        self.assertEqual(result["verification"], "failed")
        self.assertEqual(result["new_risk"], 85.0)

    def test_execution_success_but_threat_unchanged(self):
        # 1. Action Gate allows a valid action
        candidate = ResponseCandidateSchema(
            action="revoke_identity_session",
            target=self.target_arn,
            attack_path_reduction=0.8,
            business_impact="low",
            blast_radius="small",
            reversibility=True,
            confidence=0.9,
            reason="Testing threat unchanged path",
            approval_required="REQUIRES_APPROVAL"
        )
        
        policy = ResponsePolicySchema(allowlist=[AllowedActionSchema(action_type="revoke_identity_session", requires_approval=True)])
        gate_decision = ResponseActionGate.evaluate(candidate, policy, approval_state="APPROVED")
        
        # 2. Provide an initial risk score of 0
        # For 'revoke_identity_session', executor simulates new_risk = max(0, initial - 40)
        # If initial is 0, new_risk is 0, leading to 'threat unchanged'
        result = SafeResponseExecutor.execute_and_verify(
            candidate=candidate,
            gate_decision=gate_decision,
            incident_id=self.incident_id,
            initial_risk_score=0.0,
            context=self.context
        )
        
        self.assertEqual(result["execution_status"], "success")
        self.assertEqual(result["verification"], "threat unchanged")
        self.assertEqual(result["new_risk"], 0.0)


if __name__ == "__main__":
    unittest.main()
