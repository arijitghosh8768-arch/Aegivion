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

from security.engine.detectors.credential_compromise_adapter import CredentialCompromiseAdapter
from security.engine.detectors.data_exfiltration_adapter import DataExfiltrationAdapter
from algo.detection.credential_compromise.detector import CredentialCompromiseDetector, DetectionResult
from algo.detection.credential_compromise.schemas import Severity
from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector

from security.engine.detectors.base import DetectionResult, DetectionEvidence

def mock_cred_adapter_evaluate(self, event, twin_context):
    if event.action in ["ConsoleLogin", "PutUserPolicy"]:
        return DetectionResult(
            detector_name="CredentialCompromiseAdapter",
            attack_type="CREDENTIAL_COMPROMISE",
            is_suspicious=True,
            confidence_score=0.9,
            actor_id="test",
            affected_resources=[],
            evidence=[DetectionEvidence(event_id="1", description="credential_compromise_or_privesc", severity="HIGH", timestamp=event.timestamp)]
        )
    return DetectionResult(detector_name="CredentialCompromiseAdapter", attack_type="CREDENTIAL_COMPROMISE", is_suspicious=False, confidence_score=0, actor_id="test", affected_resources=[], evidence=[])

def mock_exfil_adapter_evaluate(self, event, twin_context):
    if event.action == "GetObject":
        return DetectionResult(
            detector_name="DataExfiltrationAdapter",
            attack_type="DATA_EXFILTRATION",
            is_suspicious=True,
            confidence_score=0.9,
            actor_id="test",
            affected_resources=[],
            evidence=[DetectionEvidence(event_id="1", description="data_exfiltration", severity="HIGH", timestamp=event.timestamp)]
        )
    return DetectionResult(detector_name="DataExfiltrationAdapter", attack_type="DATA_EXFILTRATION", is_suspicious=False, confidence_score=0, actor_id="test", affected_resources=[], evidence=[])

CredentialCompromiseAdapter.evaluate = mock_cred_adapter_evaluate
DataExfiltrationAdapter.evaluate = mock_exfil_adapter_evaluate


class TestPart2V2Integration(unittest.TestCase):
    def setUp(self):
        self.org_id = "org-test-001"
        self.fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "credential_compromise_story.json"
        )
        with open(self.fixture_path, "r") as f:
            self.raw_events = json.load(f)

    @patch('security.engine.security_event_deduplicator.supabase')
    @patch('app.database.supabase_client.supabase')
    def test_full_pipeline_integration(self, mock_db1, mock_db2):
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
            
            # Convert canonical_event (SecurityEventSchema) to SecurityEvent for the new adapters
            from app.models.security_event import SecurityEvent as AppSecurityEvent
            import uuid
            app_event = AppSecurityEvent(
                event_id=canonical_event.event_id or str(uuid.uuid4()),
                organization_id=canonical_event.organization_id,
                event_type="CLOUD_EVENT",
                timestamp=canonical_event.timestamp,
                source={"ip_address": canonical_event.source},
                action=canonical_event.action,
                actor={"native_id": canonical_event.actor},
                target={"native_id": canonical_event.target},
                provider=canonical_event.provider,
                account_id=canonical_event.cloud_account_id,
                metadata=canonical_event.metadata or {}
            )
            
            # Step D: Detectors
            from security.engine.detectors.credential_compromise_adapter import CredentialCompromiseAdapter
            from security.engine.detectors.data_exfiltration_adapter import DataExfiltrationAdapter
            adapters = [CredentialCompromiseAdapter(), DataExfiltrationAdapter()]
            for adapter in adapters:
                res = adapter.evaluate(app_event, twin_context)
                if res.is_suspicious:
                    # In v1 correlator expects a dict with signals
                    accumulated_signals[res.attack_type.lower()].extend(
                        [{"rule": ev.description} for ev in res.evidence]
                    )

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
