import pytest
from unittest.mock import MagicMock, patch

from app.cloud.gcp.collectors.compute import InstanceCollector
from app.cloud.gcp.sync import GCPCloudSync

@pytest.fixture
def mock_gcp_credentials():
    return MagicMock()

def test_gcp_instance_collector_mocked(mock_gcp_credentials):
    collector = InstanceCollector(mock_gcp_credentials, "test-project-123")
    collector.client = MagicMock()
    
    mock_response = {
        'items': {
            'zones/us-central1-a': {
                'instances': [
                    {
                        'id': '123456789',
                        'selfLink': 'https://www.googleapis.com/compute/v1/projects/test-project-123/zones/us-central1-a/instances/inst-1',
                        'name': 'inst-1',
                        'networkInterfaces': [
                            {
                                'network': 'https://www.googleapis.com/compute/v1/projects/test-project-123/global/networks/default',
                                'subnetwork': 'https://www.googleapis.com/compute/v1/projects/test-project-123/regions/us-central1/subnetworks/default'
                            }
                        ],
                        'serviceAccounts': [
                            {'email': 'test-sa@test-project-123.iam.gserviceaccount.com'}
                        ]
                    }
                ]
            }
        }
    }
    
    # Setup mock chain: client.instances().aggregatedList().execute() -> mock_response
    mock_request = MagicMock()
    mock_request.execute.return_value = mock_response
    collector.client.instances().aggregatedList.return_value = mock_request
    collector.client.instances().aggregatedList_next.return_value = None
    
    import asyncio
    envelopes = asyncio.run(collector.collect())
    
    assert len(envelopes) == 1
    env = envelopes[0]
    assert env["asset_id"] == "https://www.googleapis.com/compute/v1/projects/test-project-123/zones/us-central1-a/instances/inst-1"
    assert env["provider"] == "gcp"
    assert env["resource_type"] == "gcp_compute_instance"
    assert env["region"] == "us-central1-a"
    
    rels = env["relationships"]
    assert len(rels) == 3
    # Network relation
    assert any(r["target_id"] == "https://www.googleapis.com/compute/v1/projects/test-project-123/global/networks/default" and r["type"] == "LOCATED_IN" for r in rels)
    # Subnetwork relation
    assert any(r["target_id"] == "https://www.googleapis.com/compute/v1/projects/test-project-123/regions/us-central1/subnetworks/default" and r["type"] == "LOCATED_IN" for r in rels)
    # Service Account relation
    assert any(r["target_id"] == "test-sa@test-project-123.iam.gserviceaccount.com" and r["type"] == "RUNS_AS" for r in rels)

@patch('app.cloud.gcp.sync.TwinPersistenceRepository')
@patch('app.cloud.gcp.sync.supabase')
def test_gcp_sync_with_twin_persistence(mock_supabase_global, mock_repo_cls):
    mock_repo = MagicMock()
    mock_repo_cls.return_value = mock_repo
    
    # Mocking google auth logic inside GCPCloudSync
    with patch('google.oauth2.service_account.Credentials.from_service_account_info') as mock_creds:
        mock_creds.return_value = MagicMock()
        
        sync = GCPCloudSync(
            organization_id="org-gcp-test",
            cloud_account_id="acc-123",
            project_id="test-project-123",
            service_account_json='{"project_id": "test-project-123"}'
        )
        
        # Override collectors
        sync.collectors = [MagicMock()]
        
        mock_asset = {
            "asset_id": "test-sa@test-project-123.iam.gserviceaccount.com",
            "resource_type": "gcp_iam_service_account",
            "name": "test-sa@test-project-123.iam.gserviceaccount.com",
            "region": "global",
            "configuration": {},
            "relationships": []
        }
        
        import asyncio
        async def mock_collect():
            return [mock_asset]
        sync.collectors[0].collect.return_value = mock_collect()
        
        success = sync.run_sync()
        assert success is True
        
        # Validate Twin Identity creation
        mock_repo.upsert_identity.assert_called_once()
        call_args = mock_repo.upsert_identity.call_args[0]
        assert call_args[0] == "org-gcp-test"
        assert call_args[1]["native_id"] == "test-sa@test-project-123.iam.gserviceaccount.com"
        assert call_args[1]["identity_type"] == "SERVICE_ACCOUNT"
