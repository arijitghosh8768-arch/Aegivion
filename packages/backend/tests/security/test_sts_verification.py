from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from botocore.exceptions import ClientError
from app.main import app
from app.core.security import get_current_user
from app.database import get_db

def mock_get_current_user_org_a():
    return {
        "user_id": "u-123",
        "organization_id": "org-a",
        "role": "admin"
    }

def mock_get_current_user_org_b():
    return {
        "user_id": "u-456",
        "organization_id": "org-b",
        "role": "admin"
    }

class MockQuery:
    def filter(self, *args, **kwargs):
        return self
    def all(self):
        return []
    def first(self):
        return MagicMock()

class MockDB:
    def query(self, *args, **kwargs):
        return MockQuery()

def mock_get_db():
    return MockDB()

client = TestClient(app)

@patch('app.api.v1.cloud_accounts.supabase.table')
@patch('app.api.v1.cloud_accounts.AWSCloudSync')
@patch('app.api.v1.cloud_accounts.boto3.Session')
def test_valid_credentials_accepted(mock_boto3, mock_sync, mock_supabase):
    app.dependency_overrides[get_current_user] = mock_get_current_user_org_a
    app.dependency_overrides[get_db] = mock_get_db

    # Mock STS
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_session_instance = mock_boto3.return_value
    mock_session_instance.client.return_value = mock_sts

    # Mock Supabase
    mock_insert = MagicMock()
    mock_execute = MagicMock()
    mock_execute.execute.return_value = MagicMock(data=[{"id": "cloud-acc-1", "provider_account_id": "123456789012", "status": "SYNCING"}])
    mock_insert.insert.return_value = mock_execute
    mock_supabase.return_value = mock_insert

    # Mock Sync
    mock_sync_instance = mock_sync.return_value
    mock_sync_instance.run_sync.return_value = True

    response = client.post("/api/v1/cloud-accounts", json={
        "provider": "aws",
        "name": "Prod AWS",
        "aws_access_key": "AKIA...",
        "aws_secret_key": "..."
    })

    assert response.status_code == 200
    assert response.json()["provider_account_id"] == "123456789012"
    
    # Verify authoritative Account ID was inserted
    mock_insert.insert.assert_called_with({
        "organization_id": "org-a",
        "provider": "aws",
        "provider_account_id": "123456789012",
        "name": "Prod AWS",
        "status": "SYNCING"
    })
    
    app.dependency_overrides.clear()


@patch('app.api.v1.cloud_accounts.supabase.table')
@patch('app.api.v1.cloud_accounts.boto3.Session')
def test_forged_account_id_rejected(mock_boto3, mock_supabase):
    app.dependency_overrides[get_current_user] = mock_get_current_user_org_a
    app.dependency_overrides[get_db] = mock_get_db

    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_session_instance = mock_boto3.return_value
    mock_session_instance.client.return_value = mock_sts

    response = client.post("/api/v1/cloud-accounts", json={
        "provider": "aws",
        "name": "Prod AWS",
        "provider_account_id": "999999999999", # Forged ID
        "aws_access_key": "AKIA...",
        "aws_secret_key": "..."
    })

    assert response.status_code == 400
    assert "Provider account ID mismatch" in response.json()["detail"]
    mock_supabase.assert_not_called()
    
    app.dependency_overrides.clear()


@patch('app.api.v1.cloud_accounts.boto3.Session')
def test_invalid_credentials_rejected_safely(mock_boto3):
    app.dependency_overrides[get_current_user] = mock_get_current_user_org_a
    app.dependency_overrides[get_db] = mock_get_db

    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = ClientError(
        {"Error": {"Code": "InvalidClientTokenId", "Message": "The security token included in the request is invalid"}}, 
        "GetCallerIdentity"
    )
    mock_session_instance = mock_boto3.return_value
    mock_session_instance.client.return_value = mock_sts

    response = client.post("/api/v1/cloud-accounts", json={
        "provider": "aws",
        "name": "Prod AWS",
        "aws_access_key": "INVALID",
        "aws_secret_key": "INVALID"
    })

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid AWS credentials or access denied."
    # Error string doesn't leak aws exception details
    
    app.dependency_overrides.clear()

def test_missing_credentials():
    app.dependency_overrides[get_current_user] = mock_get_current_user_org_a
    app.dependency_overrides[get_db] = mock_get_db

    response = client.post("/api/v1/cloud-accounts", json={
        "provider": "aws",
        "name": "Prod AWS"
    })

    assert response.status_code == 400
    assert "AWS credentials required" in response.json()["detail"]
    
    app.dependency_overrides.clear()

@patch('app.api.v1.cloud_accounts.supabase.table')
@patch('app.api.v1.cloud_accounts.AWSCloudSync')
@patch('app.api.v1.cloud_accounts.boto3.Session')
def test_tenant_isolation(mock_boto3, mock_sync, mock_supabase):
    app.dependency_overrides[get_current_user] = mock_get_current_user_org_b
    app.dependency_overrides[get_db] = mock_get_db

    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_session_instance = mock_boto3.return_value
    mock_session_instance.client.return_value = mock_sts

    mock_insert = MagicMock()
    mock_execute = MagicMock()
    mock_execute.execute.return_value = MagicMock(data=[{"id": "cloud-acc-1", "provider_account_id": "123456789012", "status": "SYNCING"}])
    mock_insert.insert.return_value = mock_execute
    mock_supabase.return_value = mock_insert

    mock_sync_instance = mock_sync.return_value
    mock_sync_instance.run_sync.return_value = True

    response = client.post("/api/v1/cloud-accounts", json={
        "provider": "aws",
        "name": "Prod AWS",
        "aws_access_key": "AKIA...",
        "aws_secret_key": "..."
    })

    assert response.status_code == 200
    mock_insert.insert.assert_called_with({
        "organization_id": "org-b",
        "provider": "aws",
        "provider_account_id": "123456789012",
        "name": "Prod AWS",
        "status": "SYNCING"
    })
    
    app.dependency_overrides.clear()
