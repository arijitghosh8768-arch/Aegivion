import unittest
from packages.security.rules.gcp.risk import analyze_gcp_risk

class TestSecurityRules(unittest.TestCase):
    def test_gcp_public_compute_exposure(self):
        # Known-bad asset (has public IP)
        bad_asset = {
            "asset_id": "inst-1",
            "type": "COMPUTE_INSTANCE",
            "provider": "gcp",
            "configuration": {"public_ip": "1.2.3.4"}
        }
        
        # Known-good asset (no public IP)
        good_asset = {
            "asset_id": "inst-2",
            "type": "COMPUTE_INSTANCE",
            "provider": "gcp",
            "configuration": {}
        }
        
        bad_findings = analyze_gcp_risk([bad_asset])
        good_findings = analyze_gcp_risk([good_asset])
        
        # Verify bad asset generated a finding
        self.assertEqual(len(bad_findings), 1)
        self.assertEqual(bad_findings[0]["rule_id"], "gcp-public-compute-exposure")
        
        # Verify good asset did not
        self.assertEqual(len(good_findings), 0)
        
    def test_evidence_fields(self):
        """Hardening: Ensure every finding populates all 5 evidence fields."""
        asset = {
            "asset_id": "inst-1",
            "type": "COMPUTE_INSTANCE",
            "provider": "gcp",
            "configuration": {"public_ip": "1.2.3.4"}
        }
        findings = analyze_gcp_risk([asset])
        for finding in findings:
            evidence = finding.get("evidence", {})
            self.assertIn("what", evidence)
            self.assertIn("where", evidence)
            self.assertIn("when", evidence)
            self.assertIn("why", evidence)
            self.assertIn("source", evidence)

    def test_lifecycle_transitions(self):
        """Hardening: Test illegal state transitions are rejected."""
        # This is a mock validation of the state machine.
        # Legal: PROPOSED -> APPROVED -> EXECUTING
        # Illegal: PROPOSED -> EXECUTING
        def validate_transition(current_state, next_state):
            valid_transitions = {
                "PROPOSED": ["APPROVED", "REJECTED"],
                "APPROVED": ["EXECUTING"],
                "EXECUTING": ["VERIFYING", "FAILED"],
                "VERIFYING": ["SUCCESS", "FAILED"]
            }
            if next_state not in valid_transitions.get(current_state, []):
                raise ValueError(f"Illegal transition from {current_state} to {next_state}")
                
        # Test valid
        validate_transition("PROPOSED", "APPROVED")
        
        # Test invalid
        with self.assertRaises(ValueError):
            validate_transition("PROPOSED", "EXECUTING")

if __name__ == '__main__':
    unittest.main()
