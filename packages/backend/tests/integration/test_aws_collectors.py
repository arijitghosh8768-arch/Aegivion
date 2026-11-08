import pytest
from unittest.mock import MagicMock, patch
from app.cloud.aws.collectors.vpc import VPCCollector
from app.cloud.aws.collectors.security_groups import SecurityGroupCollector
from app.cloud.aws.sync import AWSCloudSync

@pytest.mark.asyncio
async def test_vpc_collector():
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_ec2 = MagicMock()
    
    mock_ec2.describe_vpcs.return_value = {
        'Vpcs': [{'VpcId': 'vpc-123', 'CidrBlock': '10.0.0.0/16', 'State': 'available'}]
    }
    mock_ec2.describe_route_tables.return_value = {
        'RouteTables': [{'RouteTableId': 'rtb-123'}]
    }
    mock_ec2.describe_internet_gateways.return_value = {
        'InternetGateways': [{'InternetGatewayId': 'igw-123'}]
    }
    mock_ec2.describe_nat_gateways.return_value = {
        'NatGateways': [{'NatGatewayId': 'nat-123'}]
    }
    
    def side_effect(service, *args, **kwargs):
        if service == 'ec2':
            return mock_ec2
        if service == 'sts':
            return mock_sts
        return MagicMock()

    mock_session.client.side_effect = side_effect
    
    collector = VPCCollector(mock_session, 'us-east-1')
    assets = await collector.collect()
    
    assert len(assets) == 1
    assert assets[0]["asset_id"] == "aws:vpc:vpc-123"
    assert "relationships" in assets[0]
    
    rel_targets = [r["target_id"] for r in assets[0]["relationships"]]
    assert "aws:igw:igw-123" in rel_targets
    assert "aws:route_table:rtb-123" in rel_targets


@pytest.mark.asyncio
async def test_security_group_collector():
    mock_session = MagicMock()
    mock_ec2 = MagicMock()
    
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{
        'SecurityGroups': [{
            'GroupId': 'sg-123',
            'GroupName': 'web-sg',
            'VpcId': 'vpc-123',
            'IpPermissions': [
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ],
            'IpPermissionsEgress': []
        }]
    }]
    mock_ec2.get_paginator.return_value = mock_paginator
    
    mock_session.client.return_value = mock_ec2
    
    collector = SecurityGroupCollector(mock_session, 'us-east-1')
    assets = await collector.collect()
    
    assert len(assets) == 1
    assert assets[0]["asset_id"] == "sg:sg-123"
    assert assets[0]["configuration"]["internet_exposed"] is True
    
    rel_targets = [r["target_id"] for r in assets[0]["relationships"]]
    assert "vpc-123" in rel_targets


@patch('app.cloud.aws.client.get_aws_session')
@patch('app.cloud.aws.sync.supabase')
def test_aws_sync_normalize_with_asset_id(mock_supabase, mock_get_aws_session):
    mock_session = MagicMock()
    mock_get_aws_session.return_value = mock_session
    sync = AWSCloudSync("org-1", "acc-1", "AKIA", "SECRET")
    
    raw_normalized = {
        "asset_id": "sg:sg-123",
        "provider": "aws",
        "type": "security_group",
        "region": "us-east-1",
        "name": "web-sg",
        "configuration": {"group_id": "sg-123"},
        "relationships": [{"type": "belongs_to", "target_id": "vpc-123", "target_type": "vpc"}]
    }
    
    result = sync._normalize(raw_normalized, "security_group")
    
    assert result["provider_resource_id"] == "sg:sg-123"
    assert result["resource_type"] == "aws_security_group"
    assert result["name"] == "web-sg"
    assert result["provider_metadata"]["raw"] is False
    assert result["provider_metadata"]["relationships"][0]["target_id"] == "vpc-123"
