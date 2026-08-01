import sys
import os
import tempfile
import yaml

# Append packages directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security.engine.loader import RuleLoader
from security.engine.validator import RuleValidator
from ai.services.llm_provider import get_llm_provider, LLMException
from app.cloud.aws.adapter import AWSProvider

def test_rule_system():
    print("\n--- Testing Rule Loading & Validator System ---")
    validator = RuleValidator()
    
    # 1. Valid Rule
    valid_rule = {
        "id": "AWS-NET-002",
        "version": 1,
        "enabled": True,
        "title": "Unencrypted RDS instances",
        "provider": "aws",
        "resource_type": "rds_instance",
        "severity": "high",
        "description": "Ensure all RDS databases are encrypted at rest."
    }
    is_valid, err_msg = validator.validate_rule_dict(valid_rule)
    print(f"Valid rule check: {'OK' if is_valid else 'FAILED'} (Error: {err_msg})")
    assert is_valid

    # 2. Duplicate Rule ID
    is_dup, err_dup = validator.validate_rule_dict(valid_rule)
    print(f"Duplicate ID check: {'OK' if not is_dup else 'FAILED'} (Error: {err_dup})")
    assert not is_dup

    # 3. Invalid Severity
    bad_sev_rule = valid_rule.copy()
    bad_sev_rule["id"] = "AWS-NET-003"
    bad_sev_rule["severity"] = "ultra-critical" # Invalid
    is_bad_sev, err_bad_sev = validator.validate_rule_dict(bad_sev_rule)
    print(f"Invalid severity check: {'OK' if not is_bad_sev else 'FAILED'} (Error: {err_bad_sev})")
    assert not is_bad_sev

    # 4. Loader scan directory
    loader = RuleLoader()
    # Path to our security/rules folder
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "security", "rules"))
    valid_loaded, load_errors = loader.load_rules_from_dir(rules_dir)
    print(f"Rules folder scan: Loaded {len(valid_loaded)} rules. Errors encountered: {len(load_errors)}")
    for err in load_errors:
        print(f"  - Load error: {err}")

def test_llm_abstraction():
    print("\n--- Testing LLM Abstraction Layer ---")
    provider = get_llm_provider()
    print(f"Active Provider selected: {provider.__class__.__name__}")
    
    try:
        res = provider.generate("Analyze vulnerable ports")
        print(f"Generate response status: {res}")
    except LLMException as e:
        print(f"Provider expectedly failed or handled credential errors: {e}")

def test_aws_identity():
    print("\n--- Testing Real AWS STS Connection Check ---")
    # Positive/Negative connection checks
    # Try using dummy/invalid credentials - should return connection false
    bad_provider = AWSProvider(access_key="fake-key", secret_key="fake-secret", default_region="us-east-1")
    is_connected = bad_provider.validate_connection()
    print(f"AWS connection validation with invalid keys: {'CONNECTED' if is_connected else 'REJECTED'}")
    assert not is_connected

if __name__ == "__main__":
    print("==================================================")
    print("Aegivion Day 9 Integration and Rule System Tests")
    print("==================================================")
    
    test_rule_system()
    test_llm_abstraction()
    test_aws_identity()
    
    print("\nAll integration checks ran successfully!")
    print("==================================================")
