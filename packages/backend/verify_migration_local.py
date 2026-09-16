import sys
from unittest.mock import MagicMock

# Force mock supabase before it gets imported
sys.modules['supabase'] = MagicMock()

import os
import asyncio
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Mock Supabase inside our client
import app.database.supabase_client as sc
mock_supabase = MagicMock()
sc.supabase = mock_supabase

from app.cloud.aws.sync import AWSCloudSync

def test_aws_vertical_slice():
    print("==================================================")
    print("Testing First Vertical Slice: AWS -> Supabase")
    print("==================================================")
    
    # 1. Mock Boto3
    with patch('boto3.Session') as MockSession:
        mock_session = MockSession.return_value
        
        # Mock EC2 client
        mock_ec2 = MagicMock()
        mock_ec2.get_paginator.return_value.paginate.return_value = [
            {'Reservations': [{'Instances': [{'InstanceId': 'i-1234567890abcdef0', 'State': {'Name': 'running'}, 'Tags': [{'Key': 'Name', 'Value': 'Real-Prod-Web'}]}]}]}
        ]
        
        # Mock S3 client
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'real-prod-bucket-123'}]}
        
        # Mock IAM client
        mock_iam = MagicMock()
        mock_iam.get_paginator.return_value.paginate.return_value = [
            {'Users': [{'UserName': 'real-admin', 'UserId': 'AIDA123'}]}
        ]
        
        def client_side_effect(service, *args, **kwargs):
            if service == 'ec2': return mock_ec2
            if service == 's3': return mock_s3
            if service == 'iam': return mock_iam
            return MagicMock()
            
        mock_session.client.side_effect = client_side_effect
        
        # 2. Mock Supabase Responses
        mock_supabase.table.return_value.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = []
        
        # 3. Initialize Worker
        sync_worker = AWSCloudSync(
            organization_id="org-test-123",
            cloud_account_id="acc-test-123",
            aws_access_key="fake-key",
            aws_secret_key="fake-secret"
        )
        
        # 4. Run Sync
        success = sync_worker.run_sync()
        
        # 5. Assertions
        assert success is True
        print("[SUCCESS] AWS Sync Worker completed without errors.")
        
        # Verify Supabase inserts
        calls = mock_supabase.table.return_value.insert.call_args_list
        assert len(calls) > 0
        
        inserted_assets = [call[0][0] for call in calls]
        print(f"[SUCCESS] Normalized and inserted {len(inserted_assets)} assets into Supabase:")
        for asset in inserted_assets:
            print(f"  -> {asset['resource_type']} | {asset['provider_resource_id']} | {asset['status']}")
            assert asset['organization_id'] == "org-test-123"
            assert asset['provider'] == "aws"

if __name__ == "__main__":
    test_aws_vertical_slice()
