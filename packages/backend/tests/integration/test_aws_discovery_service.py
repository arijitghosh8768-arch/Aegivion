import pytest
from unittest.mock import MagicMock, patch

from app.services.aws_discovery_service import AWSDiscoveryService

@pytest.fixture
def mock_persistence_repo():
    repo = MagicMock()
    return repo

@pytest.fixture
def mock_aws_session():
    session = MagicMock()
    
    # Mock STS
    sts_client = MagicMock()
    sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
    
    def client_side_effect(service_name, *args, **kwargs):
        if service_name == "sts":
            return sts_client
        return MagicMock()
        
    session.client.side_effect = client_side_effect
    return session

@patch("app.services.aws_discovery_service.get_aws_session")
@patch("app.services.aws_discovery_service.discover_iam_users")
@patch("app.services.aws_discovery_service.discover_iam_roles")
@patch("app.services.aws_discovery_service.discover_ec2_instances")
@patch("app.services.aws_discovery_service.discover_s3_buckets")
@patch("app.services.aws_discovery_service.discover_vpcs")
@patch("app.services.aws_discovery_service.discover_security_groups")
def test_aws_discovery_service_all(
    mock_sg, mock_vpc, mock_s3, mock_ec2, mock_roles, mock_users, mock_get_session, 
    mock_persistence_repo, mock_aws_session
):
    # Setup mocks
    mock_get_session.return_value = mock_aws_session
    
    mock_users.return_value = [{"arn": "arn:aws:iam::123:user/test", "UserName": "test"}]
    mock_roles.return_value = [{"arn": "arn:aws:iam::123:role/test-role", "RoleName": "test-role"}]
    mock_ec2.return_value = [{"instance_id": "i-123", "region": "us-east-1", "has_public_ip": True}]
    mock_s3.return_value = [{"arn": "arn:aws:s3:::test-bucket", "region": "us-east-1", "is_public": False}]
    mock_vpc.return_value = [{"vpc_id": "vpc-123", "region": "us-east-1"}]
    mock_sg.return_value = [{"group_id": "sg-123", "region": "us-east-1"}]
    
    service = AWSDiscoveryService(
        persistence_repo=mock_persistence_repo, 
        organization_id="org_test", 
        account_id="123456789012"
    )
    
    result = service.discover_all()
    
    assert result["status"] == "success"
    assert result["stats"]["iam_users"] == 1
    assert result["stats"]["ec2_instances"] == 1
    
    # Verify persistence interactions
    assert mock_persistence_repo.upsert_identity.call_count == 2 # 1 user, 1 role
    assert mock_persistence_repo.upsert_asset.call_count == 4 # 1 ec2, 1 s3, 1 vpc, 1 sg
    
    # Check one upsert_asset call for EC2
    mock_persistence_repo.upsert_asset.assert_any_call("org_test", {
        "resource_id": "i-123",
        "account_id": "123456789012",
        "provider": "aws",
        "type": "EC2_INSTANCE",
        "region": "us-east-1",
        "environment": "UNKNOWN",
        "internet_exposed": True,
        "metadata_json": {"instance_id": "i-123", "region": "us-east-1", "has_public_ip": True}
    })

@patch("app.services.aws_discovery_service.get_aws_session")
def test_aws_discovery_service_no_credentials(mock_get_session, mock_persistence_repo):
    mock_get_session.return_value = None
    service = AWSDiscoveryService(mock_persistence_repo, "org_test", "acc_test")
    
    result = service.discover_all()
    assert result["status"] == "error"
    assert "credentials" in result["reason"]

@patch("app.services.aws_discovery_service.get_aws_session")
def test_aws_discovery_service_tenant_isolation(mock_get_session, mock_persistence_repo, mock_aws_session):
    # If the user provides a different account ID, it should be updated by STS caller identity
    # which ensures we associate the assets with the actual account queried.
    mock_get_session.return_value = mock_aws_session
    
    service = AWSDiscoveryService(mock_persistence_repo, "org_test", "wrong_account")
    service.discover_all()
    
    assert service.account_id == "123456789012"
