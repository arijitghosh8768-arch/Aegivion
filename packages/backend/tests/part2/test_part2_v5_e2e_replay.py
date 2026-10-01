import unittest
import os
import sys
import json
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("packages/backend"))
sys.path.insert(0, os.path.abspath("."))

from security.engine.security_event_normalizer import SecurityEventNormalizer
from security.engine.security_event_deduplicator import SecurityEventDeduplicator
from security.engine.security_event_detector_adapter import SecurityEventDetectorAdapter
from security.engine.security_event_correlator import SecurityEventCorrelator
from security.engine.attack_activation_engine import AttackActivationEngine
from security.engine.attack_prediction_engine import AttackPredictionEngine
from security.engine.attack_simulation_engine import AttackSimulationEngine
from security.engine.minimum_impact_response_engine import MinimumImpactResponseEngine
from security.models.response_policy_schema import ResponsePolicySchema, GateDecision, AllowedActionSchema
from security.models.response_candidate_schema import ResponseCandidateSchema
from security.engine.response_action_gate import ResponseActionGate
from security.engine.safe_response_executor import SafeResponseExecutor
from security.models.security_replay_schema import SecurityReplaySchema
from security.engine.security_replay_engine import SecurityReplayEngine

import security.engine.attack_algorithms as algs

def mock_cred_detect(events):
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

class TestPart2V5E2EReplay(unittest.TestCase):
    def setUp(self):
        self.org_id = "org-test-001"
        self.fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "credential_compromise_story.json"
        )
        with open(self.fixture_path, "r") as f:
            self.raw_events = json.load(f)

    @patch('security.engine.security_event_deduplicator.supabase')
    @patch('app.database.supabase_client.supabase')
    @patch('security.engine.security_event_detector_adapter.detect_credential_compromise', side_effect=mock_cred_detect)
    @patch('security.engine.security_event_detector_adapter.detect_data_exfiltration', side_effect=mock_exfil_detect)
    @patch('security.engine.security_event_detector_adapter.detect_ransomware', return_value=[])
    def test_full_e2e_replay_lifecycle(self, mock_rw, mock_exfil, mock_cred, mock_db1, mock_db2):
        # Setup mocks
        mock_db1.table().select().eq().eq().execute.return_value.data = []
        dedup = SecurityEventDeduplicator(db_client=mock_db1)
        
        # 1. Pipeline Loop: simulate receiving the stream of events
        accumulated_signals = {"credential_compromise": [], "data_exfiltration": [], "ransomware": []}
        canonical_events = []
        twin_context = {}

        for raw_event in self.raw_events:
            canonical_event = SecurityEventNormalizer.normalize("aws", raw_event, self.org_id)
            canonical_events.append(canonical_event)
            dedup.is_duplicate(canonical_event)
            twin_context["target_context"] = {"arn": canonical_event.target, "sensitivity": "high"}
            
            detector_results = SecurityEventDetectorAdapter.run_detectors(canonical_event, twin_context)
            for k in accumulated_signals.keys():
                accumulated_signals[k].extend(detector_results.get(k, []))

        # 2. Correlate
        last_event = canonical_events[-1]
        incident = SecurityEventCorrelator.correlate_signals(last_event, accumulated_signals)
        
        # 3. Activation & Path
        activation = AttackActivationEngine.calculate_activation(incident)
        path_risk = AttackActivationEngine.evaluate_dynamic_path_risk(activation, twin_context)
        
        # 4. Prediction & Simulation
        predictions = AttackPredictionEngine.predict_next_stage(activation, incident)
        simulation = AttackSimulationEngine.simulate_blast_radius(incident, twin_context)
        
        # 5. Response
        responses = MinimumImpactResponseEngine.evaluate_candidates(
            incident, activation, path_risk, predictions, simulation
        )
        recommended = responses["recommended"]
        self.assertIsNotNone(recommended)
        
        # Override the mocked candidate action for executor test mapping
        recommended["action"] = "revoke_identity_session"
        candidate = ResponseCandidateSchema(**recommended)

        # 6. Gate (Approved)
        policy = ResponsePolicySchema(allowlist=[AllowedActionSchema(action_type="revoke_identity_session", requires_approval=True)])
        gate_decision = ResponseActionGate.evaluate(candidate, policy, approval_state="APPROVED")
        self.assertEqual(gate_decision, GateDecision.ALLOW)
        
        # 7. Execution & Verification
        execution = SafeResponseExecutor.execute_and_verify(
            candidate=candidate,
            gate_decision=gate_decision,
            incident_id=incident.incident_id,
            initial_risk_score=activation.activation_score,
            context=twin_context
        )
        self.assertEqual(execution["execution_status"], "success")
        self.assertEqual(execution["verification"], "threat reduced")

        # 8. Replay Serialization
        replay = SecurityReplaySchema(
            trace_id="trace-" + incident.incident_id,
            incident_id=incident.incident_id,
            events=[e.model_dump() for e in canonical_events],
            detector_results=accumulated_signals,
            correlation_storyline=incident.model_dump(),
            attack_activation=activation.model_dump(),
            dynamic_path_risk=path_risk,
            predictions=[p.model_dump() for p in predictions],
            what_if_simulation=simulation.model_dump(),
            response_candidates=[candidate.model_dump() if hasattr(candidate, "model_dump") else candidate.dict()],
            safety_decision=gate_decision.value,
            execution_result=execution
        )
        
        trace_id = SecurityReplayEngine.record_decision_trace(replay)
        
        # 9. Final Assertion of Replay
        trace = SecurityReplayEngine.replay_incident(trace_id)
        self.assertEqual(trace["safety_decision"], "ALLOW")
        self.assertEqual(trace["execution_result"]["verification"], "threat reduced")
        self.assertEqual(len(trace["events"]), 4)
        self.assertIn("credential_compromise", trace["correlation_storyline"]["attack_types"])

if __name__ == "__main__":
    unittest.main()
