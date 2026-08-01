import sys
import os
import asyncio

# Append packages directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.cloud.aws.collectors.security_groups import SecurityGroupCollector
from security.engine.risk_engine import ContextualRiskEngine, RiskLevel
from ai.services.security_brief import SecurityBriefService
from app.api.v1.explain import security_brief, BriefRequest

async def run_day13_tests():
    print("==================================================")
    print("Aegivion Day 13 Posture Brief and Risk Engine Tests")
    print("==================================================")

    # 1. Security Group Collector check
    print("\n[Step 1] Verifying SG Collector normalization logic...")
    class MockEC2Client:
        def get_paginator(self, name):
            class MockPaginator:
                def paginate(self):
                    return [{}]
            return MockPaginator()
            
    class MockSession:
        def client(self, name, region_name):
            return MockEC2Client()
            
    collector = SecurityGroupCollector(MockSession(), "ap-south-1")
    raw_sg = {
        "GroupId": "sg-12345",
        "GroupName": "prod-ssh-sg",
        "Description": "Production SSH Security Group",
        "VpcId": "vpc-09ab12cd",
        "OwnerId": "123456789012",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Anywhere"}]
            }
        ],
        "IpPermissionsEgress": []
    }
    normalized = await collector._normalize_security_group(raw_sg)
    print(f"[OK] Normalized SG ID: {normalized['asset_id']}")
    print(f"     Internet exposed: {normalized['configuration']['has_internet_exposure']}")
    assert normalized['asset_id'] == "sg:sg-12345"
    assert normalized['configuration']['has_internet_exposure'] is True

    # 2. Risk scoring engine factor tests
    print("\n[Step 2] Verifying Contextual Risk Scoring Engine scoring factors...")
    risk_engine = ContextualRiskEngine()
    
    mock_finding = {
        "severity": "high",
        "title": "SSH Exposed to internet",
        "mitre_technique": "T1078"
    }
    
    mock_asset = {
        "type": "security_group",
        "configuration": {
            "has_internet_exposure": True,
            "tags": {"Environment": "production"}
        }
    }
    
    score_obj = risk_engine.calculate_risk_score(mock_finding, mock_asset)
    print(f"[OK] Calculated Contextual Risk Score: {score_obj.score}/100")
    print(f"     Level: {score_obj.level.value}")
    print(f"     Factors details: {[(f['name'], f['value']) for f in score_obj.factors]}")
    # Capped at 100
    assert score_obj.score == 100
    assert score_obj.level == RiskLevel.CRITICAL

    # 3. Security brief aggregator checks
    print("\n[Step 3] Verifying Security Brief service compilation...")
    class MockLLMProvider:
        def generate(self, prompt):
            return "This account contains multiple exposed SSH ports in production."
            
    brief_service = SecurityBriefService(MockLLMProvider(), risk_engine)
    brief = await brief_service.generate_brief(
        "123456789012",
        [mock_finding],
        [mock_asset]
    )
    print(f"[OK] Posture brief created.")
    print(f"     Posture: {brief.overall_posture}")
    print(f"     Summary: {brief.summary}")
    print(f"     Recommendations count: {len(brief.recommended_priorities)}")
    assert brief.overall_posture == "critical_risk"
    assert len(brief.top_risks) == 1

    # 4. API Endpoints fallback
    print("\n[Step 4] Verifying Security Brief API FastAPI router handler...")
    class MockDB:
        def query(self, model):
            class MockQuery:
                def all(self):
                    return []
            return MockQuery()
            
    request = BriefRequest(cloud_account_id="all")
    api_brief = await security_brief(request, MockDB())
    print("[OK] Security Brief API endpoint completed successfully.")
    print(f"     Overall posture returned: {api_brief['overall_posture']}")
    assert api_brief['overall_posture'] in ['critical_risk', 'high_risk', 'moderate_risk', 'low_risk']

    print("\nAll Day 13 pipeline validations PASSED successfully!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_day13_tests())
