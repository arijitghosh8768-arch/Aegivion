import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
import uuid

from app.repositories.twin_persistence_repository import TwinPersistenceRepository, TenantBoundaryError
from app.cloud.aws.sync import AWSCloudSync

@pytest.fixture
def mock_supabase():
    db = MagicMock()
    return db

def test_twin_persistence_tenant_isolation(mock_supabase):
    repo = TwinPersistenceRepository(mock_supabase, "org-1")
    
    with pytest.raises(TenantBoundaryError):
        repo.upsert_asset("org-2", {"resource_id": "test"})
        
    with pytest.raises(TenantBoundaryError):
        repo.upsert_identity("org-2", {"native_id": "test"})
        
    with pytest.raises(TenantBoundaryError):
        repo.replace_asset_relationships("org-2", "source", [])

def test_twin_persistence_upsert_asset_idempotent(mock_supabase):
    repo = TwinPersistenceRepository(mock_supabase, "org-1")
    
    # Mock existing
    mock_execute = MagicMock()
    mock_execute.data = [{"id": "uuid-1", "resource_id": "res-1", "organization_id": "org-1"}]
    mock_supabase.table().select().eq().eq().execute.return_value = mock_execute
    
    res = repo.upsert_asset("org-1", {"resource_id": "res-1", "provider": "aws"})
    
    assert res["id"] == "uuid-1"
    assert res["provider"] == "aws"
    assert "updated_at" in res
    mock_supabase.table().update.assert_called()

def test_twin_persistence_relationships_preserve_history(mock_supabase):
    repo = TwinPersistenceRepository(mock_supabase, "org-1")
    
    # Mock existing relationship
    mock_execute = MagicMock()
    mock_execute.data = [{
        "id": "rel-1",
        "source_asset_id": "src-1",
        "target_asset_id": "tgt-1",
        "relationship_type": "CONNECTED_TO",
        "organization_id": "org-1",
        "first_seen_at": "2020-01-01T00:00:00Z"
    }]
    mock_supabase.table().select().eq().eq().execute.return_value = mock_execute
    
    repo.replace_asset_relationships("org-1", "src-1", [
        {"target_id": "tgt-1", "type": "CONNECTED_TO"},
        {"target_id": "tgt-2", "type": "LOCATED_IN"}
    ])
    
    # It should have called update for tgt-1 (existing) and insert for tgt-2 (new)
    assert mock_supabase.table().update.called
    assert mock_supabase.table().insert.called

@patch('app.cloud.aws.sync.TwinPersistenceRepository')
@patch('app.cloud.aws.sync.supabase')
def test_aws_sync_writes_twin_identities_and_relationships(mock_supabase_global, mock_repo_cls):
    mock_repo = MagicMock()
    mock_repo_cls.return_value = mock_repo
    
    sync = AWSCloudSync("org-1", "acc-1", "AKIA", "SECRET")
    
    # Test IAM User Asset passing through store_in_supabase
    assets = [
        {
            "provider_resource_id": "aws:iam:user:bob",
            "resource_type": "aws_iam_user",
            "name": "bob",
            "configuration": {"mfa_enabled": True},
            "provider_metadata": {
                "relationships": [{"target_id": "group1", "type": "BELONGS_TO"}]
            }
        }
    ]
    
    sync._store_in_supabase(assets)
    
    # Ensure it stored the asset itself
    assert mock_supabase_global.table().insert.called or mock_supabase_global.table().update.called
    
    # Ensure it upserted the identity
    mock_repo.upsert_identity.assert_called_once()
    call_args = mock_repo.upsert_identity.call_args[0]
    assert call_args[0] == "org-1"
    assert call_args[1]["native_id"] == "aws:iam:user:bob"
    assert call_args[1]["identity_type"] == "IAM_USER"
    assert call_args[1]["status"] == "ACTIVE"
    
    # Ensure it passed relationships to Twin repo
    mock_repo.replace_asset_relationships.assert_called_once_with(
        "org-1", "aws:iam:user:bob", [{"target_id": "group1", "type": "BELONGS_TO"}]
    )
