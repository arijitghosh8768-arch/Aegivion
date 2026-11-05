import pytest
from unittest.mock import MagicMock, patch

from app.cloud.azure.collectors.compute import VMCollector
from app.cloud.azure.collectors.network import VNetCollector
from app.cloud.azure.sync import AzureCloudSync

@pytest.fixture
def mock_azure_credential():
    return MagicMock()

def test_azure_vm_collector_mocked(mock_azure_credential):
    collector = VMCollector(mock_azure_credential, "sub-123")
    collector.client = MagicMock()
    
    mock_vm = MagicMock()
    mock_vm.id = "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
    mock_vm.name = "vm-1"
    mock_vm.location = "eastus"
    mock_vm.network_profile.network_interfaces = [MagicMock(id="/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Network/networkInterfaces/nic-1")]
    mock_vm.as_dict.return_value = {"key": "val"}
    
    collector.client.virtual_machines.list_all.return_value = [mock_vm]
    
    # We use await? The collector collect method is async.
    import asyncio
    envelopes = asyncio.run(collector.collect())
    
    assert len(envelopes) == 1
    env = envelopes[0]
    assert env["asset_id"] == mock_vm.id
    assert env["provider"] == "azure"
    assert env["resource_type"] == "azure_vm"
    
    rels = env["relationships"]
    assert len(rels) == 2
    # Check VM -> NIC relationship
    assert any(r["target_id"] == mock_vm.network_profile.network_interfaces[0].id and r["type"] == "ATTACHED_TO" for r in rels)
    # Check VM -> RG relationship
    assert any(r["target_id"] == "/subscriptions/sub-123/resourceGroups/rg-1" and r["type"] == "BELONGS_TO" for r in rels)

@patch('app.cloud.azure.sync.TwinPersistenceRepository')
@patch('app.cloud.azure.sync.supabase')
def test_azure_sync_with_twin_persistence(mock_supabase_global, mock_repo_cls, mock_azure_credential):
    mock_repo = MagicMock()
    mock_repo_cls.return_value = mock_repo
    
    # We patch ClientSecretCredential
    with patch('app.cloud.azure.sync.ClientSecretCredential', return_value=mock_azure_credential, create=True):
        sync = AzureCloudSync(
            organization_id="org-1",
            cloud_account_id="acc-1",
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret="secret",
            subscription_id="sub-123"
        )
        
        # We mock one of the collectors to return some data
        sync.collectors = [MagicMock()]
        
        mock_asset = {
            "asset_id": "azure:mi:identity1",
            "resource_type": "azure_managed_identity",
            "name": "identity1",
            "region": "eastus",
            "configuration": {},
            "relationships": [{"target_id": "scope-1", "type": "CAN_ACCESS"}]
        }
        
        # Async mock setup
        import asyncio
        async def mock_collect():
            return [mock_asset]
        sync.collectors[0].collect.return_value = mock_collect()
        
        success = sync.run_sync()
        assert success is True
        
        # Validate that asset was stored
        assert mock_supabase_global.table().insert.called or mock_supabase_global.table().update.called
        
        # Validate Twin Identity creation
        mock_repo.upsert_identity.assert_called_once()
        call_args = mock_repo.upsert_identity.call_args[0]
        assert call_args[0] == "org-1"
        assert call_args[1]["native_id"] == "azure:mi:identity1"
        assert call_args[1]["identity_type"] == "MANAGED_IDENTITY"
        
        # Validate Twin Relationship creation
        mock_repo.replace_asset_relationships.assert_called_once_with(
            "org-1", "azure:mi:identity1", [{"target_id": "scope-1", "type": "CAN_ACCESS"}]
        )
