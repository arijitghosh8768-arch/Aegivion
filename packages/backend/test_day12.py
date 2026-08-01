import sys
import os
import asyncio

# Append packages directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.cloud.aws.collectors.iam import IAMCollector
from security.engine.loader import RuleLoader
from security.engine.executor import RuleExecutor
from ai.services.remediation_engine import RemediationEngine
from app.api.v1.explain import remediate_finding

async def run_day12_tests():
    print("==================================================")
    print("Aegivion Day 12 IAM Posture and Remediation Tests")
    print("==================================================")

    # 1. IAM Collector validation checks
    print("\n[Step 1] Verifying IAM Collector normalization logic...")
    # Mock iam client and session
    class MockIAMClient:
        def list_users(self):
            return {"Users": []}
        def list_roles(self):
            return {"Roles": []}
        def list_groups(self):
            return {"Groups": []}
        def list_policies(self, Scope):
            return {"Policies": []}
            
    class MockSession:
        def client(self, name):
            return MockIAMClient()
            
    collector = IAMCollector(MockSession())
    
    # Verify policy wildcard checks
    wildcard_doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    is_admin = collector._check_admin_policy(wildcard_doc)
    wildcard_check = collector._check_wildcard_policy(wildcard_doc)
    print(f"[OK] Admin Policy check result: {is_admin}")
    print(f"     Wildcard Action check: {wildcard_check['has_wildcard_actions']}")
    assert is_admin is True
    assert wildcard_check['has_wildcard_actions'] is True

    # 2. Rule Pack loading
    print("\n[Step 2] Verifying YAML Rule Pack loading for IAM...")
    loader = RuleLoader()
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "security", "rules"))
    valid_loaded, load_errors = loader.load_rules_from_dir(rules_dir)
    print(f"[OK] Rule Loader scanned directory. Loaded {len(valid_loaded)} valid rules.")
    iam_rules = [r for r in valid_loaded if r['resource_type'] in ['iam_user', 'iam_policy']]
    for rule in iam_rules:
        print(f"     Loaded IAM Rule ID: {rule['id']} - {rule['title']} ({rule['severity']})")
    assert len(load_errors) == 0
    assert len(iam_rules) >= 6

    # 3. RuleExecutor checks
    print("\n[Step 3] Running Rule Executor on mock IAM user without MFA...")
    mock_user = {
        "asset_id": "iam:user:test-admin",
        "provider": "aws",
        "type": "iam_user",
        "region": "global",
        "name": "test-admin",
        "configuration": {
            "console_access": True,
            "mfa_enabled": False,
            "is_root_user": False,
            "access_keys": []
        }
    }
    
    executor = RuleExecutor(valid_loaded)
    findings = executor.execute(mock_user)
    print(f"[OK] Rule Execution returned {len(findings)} findings.")
    for f in findings:
         print(f"     Triggered finding: {f['rule_id']} - {f['title']} ({f['severity']})")
    triggered_ids = [f['rule_id'] for f in findings]
    assert "AWS-IAM-001" in triggered_ids

    # 4. RemediationEngine check
    print("\n[Step 4] Verifying Remediation Engine action planning...")
    class MockLLMProvider:
        def generate(self, prompt):
            return "" # Fallback trigger
            
    engine = RemediationEngine(MockLLMProvider(), None)
    plan = await engine.generate_remediation(findings[0])
    print("[OK] Remediation plan generated successfully:")
    print(f"     Priority: {plan.priority}")
    print(f"     Summary: {plan.summary}")
    print(f"     Steps count: {len(plan.steps)}")
    assert plan.priority == "high"
    assert len(plan.steps) > 0

    print("\nAll Day 12 pipeline validations PASSED successfully!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_day12_tests())
