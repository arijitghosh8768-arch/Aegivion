import unittest
from unittest.mock import patch
from pydantic import ValidationError
import os
import sys

# Ensure backend and packages are in path
# The test is executed from the project root "d:\week 1 college project\aegivion"
sys.path.insert(0, os.path.abspath("packages/backend"))
sys.path.insert(0, os.path.abspath("."))

# Models
from security.models.security_event_schema import SecurityEventSchema
from security.models.attack_activation_schema import AttackActivationSchema
from security.models.response_candidate_schema import ResponseCandidateSchema, ResponseSafety
from security.models.response_policy_schema import ResponsePolicySchema, AllowedActionSchema, GateDecision
from security.models.security_replay_schema import SecurityReplaySchema
from security.models.security_correlation_schema import SecurityCorrelationSchema

# Engines
from security.engine.security_event_normalizer import SecurityEventNormalizer
from security.engine.security_event_deduplicator import SecurityEventDeduplicator
from security.engine.security_event_detector_adapter import SecurityEventDetectorAdapter
from security.engine.security_event_correlator import SecurityEventCorrelator
from security.engine.attack_activation_engine import AttackActivationEngine
from security.engine.attack_prediction_engine import AttackPredictionEngine
from security.engine.attack_simulation_engine import AttackSimulationEngine
from security.engine.minimum_impact_response_engine import MinimumImpactResponseEngine
from security.engine.response_action_gate import ResponseActionGate
from security.engine.safe_response_executor import SafeResponseExecutor
from security.engine.security_replay_engine import SecurityReplayEngine

# Mocking the attack algorithms which might try to hit the DB or other things
import security.engine.attack_algorithms as algs
algs.detect_credential_compromise = lambda x: [{"risk": "high"}]
algs.detect_data_exfiltration = lambda x, y: []
algs.detect_ransomware = lambda x, y: []

class TestPart2V1(unittest.TestCase):
    def setUp(self):
        self.org_id = "org-v1-test"
        
    def test_security_event_schema(self):
        # Valid
        event = SecurityEventSchema(
            event_id="e1", organization_id=self.org_id, cloud_account_id="acc1",
            provider="aws", timestamp="2026-01-01T00:00:00Z",
            actor="user1", source="1.1.1.1",
            action="ConsoleLogin", target="console", metadata={}
        )
        self.assertEqual(event.event_id, "e1")
        
        # Invalid (missing required)
        with self.assertRaises(ValidationError):
            SecurityEventSchema(event_id="e1")
            
    def test_attack_activation_schema(self):
        act = AttackActivationSchema(
            activation_score=85.5, signals={}, attack_types=[], affected_assets=[],
            affected_identities=[], evidence={}
        )
        self.assertEqual(act.activation_score, 85.5)
        
        # Out of bounds
        with self.assertRaises(ValidationError):
            AttackActivationSchema(
                activation_score=105.0, signals={}, attack_types=[], affected_assets=[],
                affected_identities=[], evidence={}
            )
            
    def test_response_safety_values(self):
        # Valid enum values
        cand = ResponseCandidateSchema(
            action="revoke", target="user1", attack_path_reduction=1.0,
            business_impact="low", blast_radius="low", reversibility=True,
            confidence=1.0, reason="test", approval_required=ResponseSafety.SAFE_TO_AUTOMATE
        )
        self.assertEqual(cand.approval_required, ResponseSafety.SAFE_TO_AUTOMATE)

    def test_event_normalizer(self):
        raw_cloudtrail = {
            "eventID": "ct-1",
            "userIdentity": {"arn": "arn:aws:iam::123:user/test"},
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "requestParameters": {"bucketName": "test-bucket"},
            "eventTime": "2026-01-01T00:00:00Z",
            "recipientAccountId": "123"
        }
        event = SecurityEventNormalizer.normalize("aws", raw_cloudtrail, self.org_id)
        self.assertEqual(event.actor, "arn:aws:iam::123:user/test")
        
    def test_event_deduplicator(self):
        event = SecurityEventSchema(
            event_id="e1", organization_id=self.org_id, cloud_account_id="acc1",
            provider="aws", timestamp="2026-01-01T00:00:00Z",
            actor="user1", source="1.1.1.1",
            action="Action", target="t1", metadata={}
        )
        with patch('security.engine.security_event_deduplicator.supabase') as mock_sb:
            mock_sb.table().select().eq().eq().execute.return_value.data = []
            dedup = SecurityEventDeduplicator(db_client=mock_sb)
            is_dup = dedup.is_duplicate(event)
            self.assertFalse(is_dup)
            
            mock_sb.table().select().eq().eq().execute.return_value.data = [{"event_id": "e1"}]
            is_dup_again = dedup.is_duplicate(event)
            self.assertTrue(is_dup_again)
        
    def test_detector_adapter(self):
        event = SecurityEventSchema(
            event_id="e2", organization_id=self.org_id, cloud_account_id="acc1",
            provider="aws", timestamp="2026-01-01T00:00:00Z",
            actor="user1", source="1.1.1.1",
            action="GetObject", target="s3-bucket", metadata={}
        )
        # Adapter utilizes attack algorithms which we mocked globally
        results = SecurityEventDetectorAdapter.run_detectors(event)
        self.assertIn("credential_compromise", results)
        self.assertIn("data_exfiltration", results)
        self.assertIn("ransomware", results)
        
    def test_correlator(self):
        event = SecurityEventSchema(
            event_id="e3", organization_id=self.org_id, cloud_account_id="acc1",
            provider="aws", timestamp="2026-01-01T00:00:00Z",
            actor="user1", source="1.1.1.1",
            action="Action", target="t1", metadata={}
        )
        incident = SecurityEventCorrelator.correlate_signals(event, {"cred_compromise": [{"risk": "high"}]})
        self.assertEqual(incident.organization_id, self.org_id)
        self.assertEqual(len(incident.timeline), 1)

    def test_activation_prediction_simulation(self):
        incident = SecurityCorrelationSchema(
            incident_id="inc1", organization_id=self.org_id,
            status="OPEN", correlation_fingerprint="fp1",
            actors=["user1"], affected_assets=["t1"], timeline=[], created_at="2026-01-01T00:00:00Z"
        )
        act = AttackActivationEngine.calculate_activation(incident)
        self.assertGreaterEqual(act.activation_score, 0)
        self.assertLessEqual(act.activation_score, 100)
        
        preds = AttackPredictionEngine.predict_next_stage(act, incident)
        self.assertTrue(isinstance(preds, list))
        
        sim = AttackSimulationEngine.simulate_blast_radius(incident, {})
        self.assertTrue(hasattr(sim, "reachable_assets"))
        
    def test_minimum_impact_engine(self):
        incident = SecurityCorrelationSchema(
            incident_id="inc1", organization_id=self.org_id,
            status="OPEN", correlation_fingerprint="fp1",
            actors=["user1"], affected_assets=["t1"], timeline=[], created_at="2026-01-01T00:00:00Z"
        )
        act = AttackActivationEngine.calculate_activation(incident)
        preds = AttackPredictionEngine.predict_next_stage(act, incident)
        sim = AttackSimulationEngine.simulate_blast_radius(incident, {})
        
        response = MinimumImpactResponseEngine.evaluate_candidates(incident, act, {}, preds, sim)
        self.assertIn("recommended", response)
        
    def test_action_gate_and_executor(self):
        cand = ResponseCandidateSchema(
            action="revoke_identity_session", target="user1", attack_path_reduction=0.9,
            business_impact="low", blast_radius="low", reversibility=True,
            confidence=0.9, reason="test", approval_required=ResponseSafety.SAFE_TO_AUTOMATE
        )
        policy = ResponsePolicySchema(
            allowlist=[AllowedActionSchema(action_type="revoke_identity_session")]
        )
        
        gate_decision = ResponseActionGate.evaluate(cand, policy, approval_state="APPROVED")
        self.assertEqual(gate_decision, GateDecision.ALLOW)
        
        # Test executor
        exec_result = SafeResponseExecutor.execute_and_verify(
            cand, gate_decision, "inc1", 90.0, {}
        )
        self.assertEqual(exec_result["execution_status"], "success")
        
        # Test BLOCK
        gate_decision_block = ResponseActionGate.evaluate(cand, ResponsePolicySchema(allowlist=[]))
        self.assertEqual(gate_decision_block, GateDecision.BLOCK)
        
        exec_result_block = SafeResponseExecutor.execute_and_verify(
            cand, gate_decision_block, "inc1", 90.0, {}
        )
        self.assertEqual(exec_result_block["execution_status"], "rejected")

    def test_security_replay(self):
        trace = SecurityReplaySchema(
            trace_id="trace1", incident_id="inc1", safety_decision="ALLOW"
        )
        SecurityReplayEngine.record_decision_trace(trace)
        
        replay = SecurityReplayEngine.replay_incident("trace1")
        self.assertEqual(replay["trace_id"], "trace1")
        self.assertEqual(replay["safety_decision"], "ALLOW")

if __name__ == "__main__":
    unittest.main()
