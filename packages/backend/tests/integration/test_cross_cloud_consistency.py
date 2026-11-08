import pytest
from unittest.mock import MagicMock, patch

from app.cloud.aws.sync import AWSCloudSync
from app.cloud.azure.sync import AzureCloudSync
from app.cloud.gcp.sync import GCPCloudSync

@patch('app.cloud.aws.client.get_aws_session')
@patch('app.cloud.aws.sync.TwinPersistenceRepository')
@patch('app.cloud.azure.sync.TwinPersistenceRepository')
@patch('app.cloud.gcp.sync.TwinPersistenceRepository')
@patch('app.cloud.aws.sync.supabase')
@patch('app.cloud.azure.sync.supabase')
@patch('app.cloud.gcp.sync.supabase')
def test_cross_cloud_consistency_same_graph(
    mock_gcp_supa, mock_azure_supa, mock_aws_supa,
    mock_gcp_twin, mock_azure_twin, mock_aws_twin,
    mock_get_aws_session
):
    """
    Tests that equivalent AWS, Azure, and GCP resources can coexist in the same 
    provider-neutral Digital Twin model without creating provider-specific graph implementations.
    """
    mock_aws_session = MagicMock()
    mock_get_aws_session.return_value = mock_aws_session

    org_id = "org-unified-twin"
    
    # 1. AWS Sync
    aws_sync = AWSCloudSync(org_id, "aws-acc", "key", "secret")
    mock_aws_col = MagicMock()
    mock_aws_col.resource_type = "iam_role"
    aws_sync.collectors = [mock_aws_col]
    aws_asset = {
        "asset_id": "arn:aws:iam::123456789012:role/DemoRole",
        "resource_type": "aws_iam_role",
        "name": "DemoRole",
        "region": "global",
        "configuration": {},
        "relationships": []
    }
    async def aws_collect(): return [aws_asset]
    aws_sync.collectors[0].collect.return_value = aws_collect()
    
    # 2. Azure Sync
    with patch('app.cloud.azure.sync.ClientSecretCredential', create=True):
        azure_sync = AzureCloudSync(org_id, "azure-acc", "tenant", "client", "secret", "sub")
    mock_az_col = MagicMock()
    mock_az_col.resource_type = "managed_identity"
    azure_sync.collectors = [mock_az_col]
    azure_asset = {
        "asset_id": "azure:mi:DemoIdentity",
        "resource_type": "azure_managed_identity",
        "name": "DemoIdentity",
        "region": "global",
        "configuration": {},
        "relationships": []
    }
    async def azure_collect(): return [azure_asset]
    azure_sync.collectors[0].collect.return_value = azure_collect()

    # 3. GCP Sync
    with patch('google.oauth2.service_account.Credentials.from_service_account_info') as mock_creds:
        mock_creds.return_value = MagicMock()
        gcp_sync = GCPCloudSync(org_id, "gcp-acc", "proj", "{}")
    mock_gcp_col = MagicMock()
    mock_gcp_col.resource_type = "iam_service_account"
    gcp_sync.collectors = [mock_gcp_col]
    gcp_asset = {
        "asset_id": "test-sa@test-project-123.iam.gserviceaccount.com",
        "resource_type": "gcp_iam_service_account",
        "name": "test-sa@test-project-123.iam.gserviceaccount.com",
        "region": "global",
        "configuration": {},
        "relationships": []
    }
    async def gcp_collect(): return [gcp_asset]
    gcp_sync.collectors[0].collect.return_value = gcp_collect()
    
    # Run all
    aws_sync.run_sync()
    azure_sync.run_sync()
    gcp_sync.run_sync()
    
    # Verify AWS hit TwinPersistenceRepository correctly
    mock_aws_twin.return_value.upsert_identity.assert_called_with(org_id, {
        "account_id": "aws-acc",
        "provider": "aws",
        "native_id": "arn:aws:iam::123456789012:role/DemoRole",
        "identity_type": "IAM_ROLE",
        "name": "DemoRole",
        "status": "ACTIVE",
        "metadata": {}
    })
    
    # Verify Azure hit TwinPersistenceRepository correctly
    mock_azure_twin.return_value.upsert_identity.assert_called_with(org_id, {
        "account_id": "azure-acc",
        "provider": "azure",
        "native_id": "azure:mi:DemoIdentity",
        "identity_type": "MANAGED_IDENTITY",
        "name": "DemoIdentity",
        "status": "ACTIVE",
        "metadata": {}
    })
    
    # Verify GCP hit TwinPersistenceRepository correctly
    mock_gcp_twin.return_value.upsert_identity.assert_called_with(org_id, {
        "account_id": "gcp-acc",
        "provider": "gcp",
        "native_id": "test-sa@test-project-123.iam.gserviceaccount.com",
        "identity_type": "SERVICE_ACCOUNT",
        "name": "test-sa@test-project-123.iam.gserviceaccount.com",
        "status": "ACTIVE",
        "metadata": {}
    })
    
    # The models show that despite differing cloud architectures, 
    # all providers resolve to identical function calls mapping into the unified Digital Twin org namespace.
