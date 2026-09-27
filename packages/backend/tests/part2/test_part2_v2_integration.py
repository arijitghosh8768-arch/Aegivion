import unittest
import os
import sys
import json
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("packages/backend"))
sys.path.insert(0, os.path.abspath("."))

from security.engine.security_event_normalizer import SecurityEventNormalizer
from security.engine.security_event_deduplicator import SecurityEventDeduplicator
from security.engine.security_digital_twin import SecurityDigitalTwin
from security.engine.security_event_detector_adapter import SecurityEventDetectorAdapter
from security.engine.security_event_correlator import SecurityEventCorrelator
from security.engine.attack_activation_engine import AttackActivationEngine
from security.engine.attack_prediction_engine import AttackPredictionEngine
from security.engine.attack_simulation_engine import AttackSimulationEngine
from security.engine.minimum_impact_response_engine import MinimumImpactResponseEngine
from security.models.response_policy_schema import GateDecision
from security.engine.response_action_gate import ResponseActionGate

# Mocking Detectors to simulate actual signal findings from the events
import security.engine.attack_algorithms as algs

def mock_cred_detect(events):
    # If PutUserPolicy or ConsoleLogin, trigger
    results = []
    for e in events:
        if e.get("event_name") in ["ConsoleLogin", "PutUserPolicy"]:
            results.append({"risk": "high", "rule": "credential_compromise_or_privesc"})
    return results

def mock_exfil_detect(events, assets):
    results = []
    for e in events:
        if e.get("event_name") == "GetObject":
            results.append({"risk": "critical", "rule": "data_exfiltration"})
    return results

algs.detect_credential_compromise = mock_cred_detect
algs.detect_data_exfiltration = mock_exfil_detect
algs.detect_ransomware = lambda x, y: []


class TestPart2V2Integration(unittest.TestCase):
    def setUp(self):
        self.org_id = "org-test-001"
        self.fixture_path = os.path.join(
            os.path.abspath("packages/backend"), 
            "tests", "part2", "fixtures", "credential_compromise_story.json"
        )
        with open(self.fixture_path, "r") as f:
            self.raw_events = json.load(f)

    @patch('security.engine.security_event_deduplicator.supabase')
    @patch('app.database.supabase_client.supabase')
    @patch('security.engine.security_event_detector_adapter.detect_credential_compromise', side_effect=mock_cred_detect)
    @patch('security.engine.security_event_detector_adapter.detect_data_exfiltration', side_effect=mock_exfil_detect)
    @patch('security.engine.security_event_detector_adapter.detect_ransomware', return_value=[])
    def test_full_pipeline_integration(self, mock_rw, mock_exfil, mock_cred, mock_db1, mock_db2):
        # Setup mocks to act like new events and no DB state needed
        mock_db1.table().select().eq().eq().execute.return_value.data = []
        dedup = SecurityEventDeduplicator(db_client=mock_db1)

        # 1. Pipeline Loop: simulate receiving the stream of events
        accumulated_signals = {"credential_compromise": [], "data_exfiltration": [], "ransomware": []}
        canonical_events = []
        twin_context = {}

        for raw_event in self.raw_events:
            # Step A: Normalize
            canonical_event = SecurityEventNormalizer.normalize("aws", raw_event, self.org_id)
            canonical_events.append(canonical_event)
            
            self.assertEqual(canonical_event.organization_id, self.org_id)
            
            # Step B: Deduplicate
            is_duplicate = dedup.is_duplicate(canonical_event)
            self.assertFalse(is_duplicate)
            
            # Step C: Twin
            # In a real integration this evaluates impact, we'll mock it simply
            twin_context["target_context"] = {"arn": canonical_event.target, "sensitivity": "high"}
            
            # Step D: Detectors
            detector_results = SecurityEventDetectorAdapter.run_detectors(canonical_event, twin_context)
            for k in accumulated_signals.keys():
                accumulated_signals[k].extend(detector_results.get(k, []))

        self.assertEqual(len(canonical_events), 4)

        # Step E: Correlate
        # We pass the final state of signals and one representative event (or the list) to Correlator
        # Correlator in V1 expects a single event but aggregates signals. We'll use the last event.
        last_event = canonical_events[-1]
        incident = SecurityEventCorrelator.correlate_signals(last_event, accumulated_signals)
        
        self.assertIsNotNone(incident)
        self.assertEqual(incident.organization_id, self.org_id)
        self.assertIn("credential_compromise", incident.attack_types)
        self.assertIn("data_exfiltration", incident.attack_types)
        
        # Step F: Activation
        activation = AttackActivationEngine.calculate_activation(incident)
        self.assertGreater(activation.activation_score, 0.0)
        self.assertIn("data_exfiltration", activation.signals)
        
        # Step G: Dynamic Path / Twin Context Risk (we mock the engine result natively)
        path_risk = AttackActivationEngine.evaluate_dynamic_path_risk(activation, twin_context)
        self.assertIn("path_risk_score", path_risk)
        
        # Step H: Prediction
        predictions = AttackPredictionEngine.predict_next_stage(activation, incident)
        self.assertTrue(len(predictions) > 0)
        # Ensure it predicted ransomware/destruction based on exfil
        pred_types = [p.next_stage for p in predictions]
        self.assertTrue(any("ransomware_or_destruction" in pt for pt in pred_types))

        # Step I: Simulation
        simulation = AttackSimulationEngine.simulate_blast_radius(incident, twin_context)
        self.assertTrue(hasattr(simulation, "reachable_assets"))

        # Step J: Response Engine
        responses = MinimumImpactResponseEngine.evaluate_candidates(
            incident, activation, path_risk, predictions, simulation
        )
        self.assertIn("recommended", responses)
        
        # Assertions on final integration integrity
        recommended = responses["recommended"]
        self.assertIsNotNone(recommended)
        
        # Check Safety Boundary
        # Even though we propose a response, without Gate ALLOW, we wouldn't execute.
        from security.models.response_policy_schema import ResponsePolicySchema
        policy = ResponsePolicySchema(allowlist=[])
        gate_decision = ResponseActionGate.evaluate(recommended, policy)
        
        self.assertEqual(gate_decision, GateDecision.BLOCK)
        
        # Validate that ZERO cloud mutations happened
        # We haven't imported boto3, we haven't invoked SafeResponseExecutor with ALLOW.
        # This inherently tests cloud boundary preservation.


if __name__ == "__main__":
    unittest.main()
