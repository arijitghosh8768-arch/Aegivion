import os
import sys
import boto3
import json
import datetime
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath("packages/backend"))
sys.path.insert(0, os.path.abspath("."))

from security.engine.security_event_normalizer import SecurityEventNormalizer
from security.engine.security_event_detector_adapter import SecurityEventDetectorAdapter

def v6_cb_fetch_real_cloudtrail_event(account_id):
    """
    V6-Cb: Fetch an actual CloudTrail event directly from AWS and pass it to Aegivion.
    """
    print("\n--- V6-Cb: Actual CloudTrail Event Fetching ---")
    
    cloudtrail = boto3.client('cloudtrail')
    
    # We look for a recent event in the last 60 minutes
    start_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=60)
    
    print("Querying CloudTrail for recent write/management events...")
    try:
        response = cloudtrail.lookup_events(
            StartTime=start_time,
            MaxResults=10
        )
        events = response.get('Events', [])
        
        if not events:
            print("⚠️  No CloudTrail events found in the last 60 minutes.")
            print("Please perform a safe manual action in AWS (e.g. creating a role, attaching a policy, or logging into the console) and wait ~5-15 mins for CloudTrail to register it.")
            sys.exit(1)
            
        # Select the most recent CloudTrail event
        raw_ct_str = events[0].get('CloudTrailEvent')
        if not raw_ct_str:
            print("❌ Found an event but CloudTrailEvent payload was missing.")
            sys.exit(1)
            
        real_event = json.loads(raw_ct_str)
        print(f"✅ Fetched real CloudTrail event: {real_event.get('eventName')} by {real_event.get('userIdentity', {}).get('arn')}")
        return real_event
        
    except Exception as e:
        print(f"❌ Failed to fetch CloudTrail events: {e}")
        sys.exit(1)


def v6_d_real_detector_integration(real_event, org_id):
    """
    V6-D: Pass the real CloudTrail event through the ingestion and detection pipeline.
    """
    print("\n--- V6-D: Real Event Normalization & Detection ---")
    
    try:
        # 1. Normalization
        canonical = SecurityEventNormalizer.normalize("aws", real_event, org_id)
        print(f"✅ Real Event Normalized -> ID: {canonical.event_id}, Action: {canonical.action}")
        
        # 2. Setup mock digital twin context based on the real event's target
        twin_context = {
            "target_context": {
                "arn": canonical.target,
                "sensitivity": "medium"  # Mocked sensitivity for the real resource
            }
        }
        
        # 3. Detection
        # We send the real event to the actual detectors to ensure they can parse a real structure
        detector_results = SecurityEventDetectorAdapter.run_detectors(canonical, twin_context)
        
        print(f"✅ Detectors successfully processed the real event.")
        print(f"   Credential Compromise Findings : {len(detector_results.get('credential_compromise', []))}")
        print(f"   Data Exfiltration Findings     : {len(detector_results.get('data_exfiltration', []))}")
        print(f"   Ransomware Findings            : {len(detector_results.get('ransomware', []))}")
        
        if any(detector_results.values()):
            print("⚠️  The real event successfully triggered a detection rule!")
        else:
            print("ℹ️  The real event was processed cleanly but did not trigger any hostile detection rules.")
            
    except Exception as e:
        print(f"❌ Pipeline crashed while processing the real CloudTrail event: {e}")
        sys.exit(1)

def verify_test_account():
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    account_id = identity['Account']
    expected = os.getenv("EXPECTED_AWS_ACCOUNT_ID")
    
    if not expected or account_id != expected:
        print(f"❌ Safety Abort: Connected to {account_id}, but EXPECTED_AWS_ACCOUNT_ID is {expected}.")
        sys.exit(1)
        
    return account_id

def main():
    print("==================================================")
    print(" Aegivion V6 AWS Real CloudTrail & Detection (Cb-D)")
    print("==================================================")
    
    account_id = verify_test_account()
    org_id = "org-v6-test"
    
    real_event = v6_cb_fetch_real_cloudtrail_event(account_id)
    v6_d_real_detector_integration(real_event, org_id)
    
    print("\n🎉 Phase V6-Cb and V6-D completed successfully.")

if __name__ == "__main__":
    main()
