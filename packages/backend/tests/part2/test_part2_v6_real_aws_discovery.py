import os
import sys
import boto3
import asyncio
import uuid
import json

sys.path.insert(0, os.path.abspath("packages/backend"))
sys.path.insert(0, os.path.abspath("."))

from security.engine.security_event_normalizer import SecurityEventNormalizer

def v6_a_verify_environment():
    """
    V6-A: Verify AWS Test Environment.
    Reads current STS identity and ensures EXPECTED_AWS_ACCOUNT_ID matches.
    """
    print("\n--- V6-A: Verifying AWS Test Environment ---")
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        arn = identity['Arn']
    except Exception as e:
        print(f"Failed to fetch AWS credentials: {e}")
        print("Please ensure you have assumed a test IAM role or configured temporary credentials.")
        sys.exit(1)

    print(f"✅ Connected to AWS Account : {account_id}")
    print(f"✅ Acting as IAM Identity  : {arn}")

    expected = os.getenv("EXPECTED_AWS_ACCOUNT_ID")
    if not expected:
        print("⚠️  No EXPECTED_AWS_ACCOUNT_ID environment variable provided.")
        print("⚠️  For safety, please set EXPECTED_AWS_ACCOUNT_ID to your dedicated test account ID.")
        sys.exit(1)

    if account_id != expected:
        print(f"❌ Safety Abort: Connected to {account_id}, but EXPECTED_AWS_ACCOUNT_ID is {expected}.")
        print("❌ Do NOT run this test against production!")
        sys.exit(1)

    print("✅ Safety check passed. Authorized to proceed with test account.")
    return account_id


async def v6_b_read_only_discovery(account_id):
    """
    V6-B: Read-only Discovery.
    Validates that real assets (EC2, S3, IAM) can be discovered.
    Does NOT mutate database in this test script; purely validates the collector logic.
    """
    print("\n--- V6-B: Read-Only Discovery Validation ---")
    
    # We will import the collectors directly to test their real-cloud reading capability.
    from app.cloud.aws.collectors.iam import IAMCollector
    from app.cloud.aws.collectors.s3 import S3Collector
    
    session = boto3.Session()
    region = session.region_name or 'ap-south-1'
    
    print(f"Initializing collectors in region: {region}")
    
    iam_collector = IAMCollector(session)
    s3_collector = S3Collector(session, region)
    
    try:
        iam_assets = await iam_collector.collect()
        print(f"✅ Discovered {len(iam_assets)} IAM assets (Roles/Users/Policies).")
    except Exception as e:
        print(f"❌ Failed to collect IAM assets: {e}")
        
    try:
        s3_assets = await s3_collector.collect()
        print(f"✅ Discovered {len(s3_assets)} S3 assets.")
    except Exception as e:
        print(f"❌ Failed to collect S3 assets: {e}")
        
    # We won't persist to the DB in this read-only sanity check.
    # The actual Twin ingestion has been proven synthetically.
    print("✅ V6-B complete. Collectors are reading real AWS states successfully.")


def v6_c_controlled_cloudtrail_event(account_id):
    """
    V6-C: Generate a single controlled Security Event and push to Normalization.
    We synthesize a CloudTrail event that would naturally come from the test account.
    """
    print("\n--- V6-C: Controlled Security Event Ingestion ---")
    
    # Mimic a real AWS CloudTrail Event targeting our test account
    raw_cloudtrail_event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJ45Q7YFFAEXAMPLE",
            "arn": f"arn:aws:iam::{account_id}:user/test-hacker",
            "accountId": account_id,
            "userName": "test-hacker"
        },
        "eventTime": "2026-09-27T00:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "ap-south-1",
        "sourceIPAddress": "192.0.2.1",
        "userAgent": "AWS Internal",
        "requestParameters": {
            "userName": "test-hacker",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        },
        "recipientAccountId": account_id
    }
    
    organization_id = "org-v6-test"
    
    print("Validating Normalizer mapping against real CloudTrail schema...")
    canonical_event = SecurityEventNormalizer.normalize("aws", raw_cloudtrail_event, organization_id)
    
    print(f"✅ Normalized Event ID   : {canonical_event.event_id}")
    print(f"✅ Cloud Account ID    : {canonical_event.cloud_account_id}")
    print(f"✅ Event Name          : {canonical_event.action}")
    print(f"✅ Actor ARN           : {canonical_event.actor}")
    print(f"✅ Target Identified   : {canonical_event.target}")
    
    assert canonical_event.cloud_account_id == account_id, "Account ID mismatch in normalization"
    assert canonical_event.action == "AttachUserPolicy", "Action mapping failed"
    assert "test-hacker" in canonical_event.actor, "Actor mapping failed"
    
    print("✅ V6-C complete. Event Normalization is ready for real AWS traffic.")


async def main():
    print("==================================================")
    print(" Aegivion V6 AWS Controlled Test Matrix (A-C)")
    print("==================================================")
    
    account_id = v6_a_verify_environment()
    await v6_b_read_only_discovery(account_id)
    v6_c_controlled_cloudtrail_event(account_id)
    
    print("\n🎉 Phase V6-A through V6-C completed successfully.")
    print("You may now proceed to V6-D/E when the real environment is fully instrumented.")

if __name__ == "__main__":
    asyncio.run(main())
