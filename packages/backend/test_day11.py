import sys
import os
import asyncio

# Append packages directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.cloud.aws.collectors.s3 import S3Collector
from security.engine.loader import RuleLoader
from security.engine.executor import RuleExecutor
from app.api.v1.explain import explain_finding, ExplainRequest

async def run_day11_tests():
    print("==================================================")
    print("Aegivion Day 11 Pipeline and Rule Pack Tests")
    print("==================================================")

    # 1. S3 normalizer checks
    print("\n[Step 1] Verifying S3 Collector normalization checks...")
    # Mock s3 client and session
    class MockS3Client:
        def list_buckets(self):
            return {"Buckets": []}
        def get_bucket_encryption(self, Bucket):
            return {}
        def get_bucket_versioning(self, Bucket):
            return {}
        def get_public_access_block(self, Bucket):
            return {}
        def get_bucket_policy(self, Bucket):
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy")
        def get_bucket_logging(self, Bucket):
            return {}
        def get_bucket_tagging(self, Bucket):
            return {}
        def get_bucket_acl(self, Bucket):
            return {}
            
    class MockSession:
        def client(self, name):
            return MockS3Client()
            
    collector = S3Collector(MockSession(), "ap-south-1")
    normalized_bucket = await collector._normalize_bucket("aegivion-customer-data-bucket", "ap-south-1")
    
    print(f"[OK] Normalized S3 asset: {normalized_bucket['asset_id']}")
    print(f"     Encryption: {normalized_bucket['configuration']['encryption_enabled']}")
    print(f"     Versioning: {normalized_bucket['configuration']['versioning_enabled']}")
    # Asserting mock default checks (which should return False/empty defaults)
    assert normalized_bucket['type'] == "s3"
    assert normalized_bucket['configuration']['encryption_enabled'] is False

    # 2. Rule Pack loading
    print("\n[Step 2] Verifying YAML Rule Pack loading from s3/network directories...")
    loader = RuleLoader()
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "security", "rules"))
    valid_loaded, load_errors = loader.load_rules_from_dir(rules_dir)
    print(f"[OK] Rule Loader scanned directory. Loaded {len(valid_loaded)} valid rules.")
    for rule in valid_loaded:
        print(f"     Loaded Rule ID: {rule['id']} - {rule['title']} ({rule['severity']})")
    assert len(load_errors) == 0
    assert len(valid_loaded) >= 6

    # 3. RuleExecutor checks
    print("\n[Step 3] Running Rule Executor on unencrypted bucket...")
    executor = RuleExecutor(valid_loaded)
    findings = executor.execute(normalized_bucket)
    print(f"[OK] Rule Execution returned {len(findings)} findings.")
    for f in findings:
         print(f"     Triggered finding: {f['rule_id']} - {f['title']} ({f['severity']})")
    triggered_ids = [f['rule_id'] for f in findings]
    assert "AWS-S3-002" in triggered_ids # Encryption disabled

    # 4. Explain API check
    print("\n[Step 4] Verifying Explain API router handler fallback...")
    class MockDB:
        def query(self, model):
            class MockQuery:
                def filter(self, *args, **kwargs):
                    class MockFilter:
                        def first(self):
                            return None
                    return MockFilter()
            return MockQuery()

    request = ExplainRequest(finding_id="F-001")
    explanation = explain_finding("F-001", request, MockDB())
    print("[OK] Explain API successfully returned explanation context:")
    print(f"     Finding ID: {explanation['finding_id']}")
    print(f"     Root Cause: {explanation.get('root_cause', 'N/A')}")
    print(f"     Remediation Recs Count: {len(explanation.get('recommendations', []))}")
    assert explanation['finding_id'] == "F-001"
    assert len(explanation['recommendations']) > 0

    print("\nAll Day 11 pipeline validations PASSED successfully!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_day11_tests())
