import sys
import os
import asyncio

# Append packages directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.cloud.aws.collectors.ec2 import EC2Collector
from security.engine.executor import RuleExecutor
from ai.services.prompt_builder import PromptBuilder, PromptContext
from ai.services.llm_provider import LocalProvider

async def run_day10_tests():
    print("==================================================")
    print("Aegivion Day 10 Pipeline and Abstractions Tests")
    print("==================================================")

    # 1. Test normalization with mock raw instance
    print("\n[Step 1] Verifying Collector normalization output...")
    # Mock boto3 session object
    class MockEC2Client:
        def get_paginator(self, name):
            class MockPaginator:
                def paginate(self):
                    return [{}]
            return MockPaginator()
    class MockSession:
        def client(self, service, region_name):
            return MockEC2Client()
            
    collector = EC2Collector(MockSession(), "ap-south-1")
    raw_instance = {
        "InstanceId": "i-0123456789abcdef0",
        "InstanceType": "t3.medium",
        "State": {"Name": "running"},
        "PublicIpAddress": "54.210.12.34",
        "PrivateIpAddress": "10.0.1.4",
        "VpcId": "vpc-12345678",
        "SubnetId": "subnet-87654321",
        "SecurityGroups": [{"GroupId": "sg-9999", "GroupName": "public-ssh"}],
        "Tags": [{"Key": "Name", "Value": "prod-web-server"}]
    }
    normalized = await collector._normalize_instance(raw_instance)
    print(f"[OK] Normalized asset ID: {normalized['asset_id']}")
    print(f"     Name: {normalized['name']}")
    print(f"     Relationships mapped count: {len(normalized['relationships'])}")
    assert normalized['asset_id'] == "i-0123456789abcdef0"
    assert normalized['configuration']['state'] == "running"

    # 2. Test Rule Condition Evaluation with nested field paths
    print("\n[Step 2] Verifying Rule Condition Executor with nested field path checks...")
    rules_config = [
        {
            "id": "AWS-EC2-001",
            "version": 1,
            "enabled": True,
            "title": "EC2 instance running as t3.medium",
            "provider": "aws",
            "resource_type": "ec2",
            "severity": "info",
            "description": "Information rule monitoring instance sizing.",
            "conditions": [
                {
                    "field": "configuration.instance_type",
                    "operator": "equals",
                    "value": "t3.medium"
                },
                {
                    "field": "configuration.state",
                    "operator": "equals",
                    "value": "running"
                }
            ],
            "mitre_technique": "T1078",
            "remediation": ["Review sizing controls."]
        }
    ]
    
    executor = RuleExecutor(rules_config)
    findings = executor.execute(normalized)
    print(f"[OK] Rule Execution processed. Findings returned: {len(findings)}")
    assert len(findings) == 1
    finding = findings[0]
    print(f"     Finding Title: {finding['title']}")
    print(f"     Calculated Evidence keys: {list(finding['evidence'].keys())}")
    assert "configuration.instance_type" in finding["evidence"]

    # 3. Test Prompt Builder
    print("\n[Step 3] Verifying Grounded Prompt Builder context generation...")
    context = PromptContext(
        finding=finding,
        asset=normalized,
        evidence=finding["evidence"],
        severity=finding["severity"],
        risk_score=45.0,
        mitre_technique="T1078",
        mitre_tactic="Initial Access"
    )
    builder = PromptBuilder()
    prompt = builder.build_prompt(context)
    
    print("--------------------------------------------------")
    print(prompt[:400] + "\n... [truncated] ...")
    print("--------------------------------------------------")
    print("[OK] Factual prompt built correctly!")
    assert "GROUNDING RULES:" in prompt
    assert "SECURITY FINDING:" in prompt
    assert "ASSET DETAILS:" in prompt

    print("\nAll Day 10 pipeline validations PASSED successfully!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_day10_tests())
