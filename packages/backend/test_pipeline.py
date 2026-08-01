import sys
import os
import asyncio

# Append packages directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security.schema.validation import validate_asset, validate_finding
from security.tests.mock_assets import MOCK_SECURITY_GROUP_ASSET
from security.engine.detection_pipeline import DetectionPipeline
from ai.services.aggregator import AIContextAggregator
from ai.tests.mock_findings import MOCK_FINDINGS

async def run_pipeline_test():
    print("==================================================")
    print("Aegivion Day 8 Security Pipeline Integration Test")
    print("==================================================")

    # 1. Load mock vulnerable security group asset
    print("\n[Step 1] Loading Mock AWS Security Group Asset...")
    asset = MOCK_SECURITY_GROUP_ASSET
    print(f"Asset ID: {asset['asset_id']}, Name: {asset['name']}, Type: {asset['type']}")

    # 2. Asset Validator
    print("\n[Step 2] Validating asset against normalized schema...")
    is_valid, err_msg = validate_asset(asset)
    if is_valid:
        print("[OK] Asset successfully validated against JSON schema contract!")
    else:
        print(f"[ERROR] Asset validation failed: {err_msg}")
        return False

    # 2b. Validate malformed asset rejection
    print("\n[Step 2b] Testing rejection of malformed assets...")
    malformed_asset = {
        "asset_id": "malformed-001",
        "provider": "invalid-provider-name", # Invalid enum values
        "type": "ec2",
        # Missing fields like region, name, configuration, etc.
    }
    is_malformed_valid, err_malformed = validate_asset(malformed_asset)
    if not is_malformed_valid:
        print(f"[OK] Successfully rejected malformed asset! Error: {err_malformed}")
    else:
        print("[ERROR] Malformed asset was incorrectly accepted!")
        return False

    # 3. Detection Engine evaluation
    print("\n[Step 3] Running Security Detection Engine on valid asset...")
    pipeline = DetectionPipeline()
    detection_results = await pipeline.evaluate_resource(asset)
    
    if len(detection_results) > 0:
        print(f"[OK] Non-compliance detected! Found {len(detection_results)} vulnerability.")
        det = detection_results[0]
        print(f"   Rule Triggered: {det.rule_id} ({det.rule_name})")
        print(f"   Severity: {det.severity}")
        print(f"   Risk Score: {det.risk_score}")
    else:
        print("[ERROR] Detection engine did not find compliance violations!")
        return False

    # 4. Generate Mock Finding matching the schema contract
    print("\n[Step 4] Building finding conforming to security intake contract...")
    finding = {
        "finding_id": "F-001",
        "asset_id": asset["asset_id"],
        "rule_id": det.rule_id,
        "title": det.rule_name,
        "severity": det.severity,
        "risk_score": det.risk_score,
        "evidence": {
            "port": 22,
            "protocol": "tcp",
            "cidr": "0.0.0.0/0"
        }
    }
    
    is_finding_valid, err_finding = validate_finding(finding)
    if is_finding_valid:
        print("[OK] Security finding successfully validated against schema contract!")
    else:
        print(f"[ERROR] Security finding validation failed: {err_finding}")
        return False

    # 5. Context Builder & AI prompt input
    print("\n[Step 5] Building deterministic context for AI Reasoning...")
    ai_context = AIContextAggregator.build_context(finding, asset)
    print("--------------------------------------------------")
    print(ai_context)
    print("--------------------------------------------------")
    print("[OK] AI Context constructed successfully!")

    print("\nDay 8 Mock Pipeline Integration Test: SUCCESS!")
    print("==================================================")
    return True

if __name__ == "__main__":
    asyncio.run(run_pipeline_test())
