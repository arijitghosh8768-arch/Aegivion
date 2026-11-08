import pytest
from unittest.mock import MagicMock
from app.cloud.aws.collectors.rds import RDSCollector
from app.cloud.aws.scan.orchestrator import ScanOrchestrator

@pytest.mark.asyncio
async def test_rds_collector_normalize():
    """Verify that RDSCollector correctly normalizes AWS describe_db_instances output"""
    mock_session = MagicMock()
    mock_rds_client = MagicMock()
    mock_session.client.return_value = mock_rds_client

    mock_paginator = MagicMock()
    mock_rds_client.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "prod-db-postgres-01",
                    "DBInstanceArn": "arn:aws:rds:ap-south-1:123456789012:db:prod-db-postgres-01",
                    "Engine": "postgres",
                    "EngineVersion": "15.4",
                    "DBInstanceClass": "db.m5.large",
                    "DBInstanceStatus": "available",
                    "MasterUsername": "postgres_admin",
                    "AllocatedStorage": 100,
                    "StorageType": "gp3",
                    "StorageEncrypted": True,
                    "KmsKeyId": "arn:aws:kms:ap-south-1:123456789012:key/abc-123",
                    "MultiAZ": True,
                    "PubliclyAccessible": False,
                    "AutoMinorVersionUpgrade": True,
                    "BackupRetentionPeriod": 7,
                    "Endpoint": {
                        "Address": "prod-db-postgres-01.c123.ap-south-1.rds.amazonaws.com",
                        "Port": 5432
                    },
                    "DBSubnetGroup": {
                        "VpcId": "vpc-0123456789abcdef0",
                        "Subnets": [
                            {"SubnetIdentifier": "subnet-012345"},
                            {"SubnetIdentifier": "subnet-067890"}
                        ]
                    },
                    "VpcSecurityGroups": [
                        {
                            "VpcSecurityGroupId": "sg-0987654321fedcba0",
                            "Status": "active"
                        }
                    ],
                    "TagList": [
                        {"Key": "Environment", "Value": "Production"},
                        {"Key": "Project", "Value": "Aegivion"}
                    ]
                }
            ]
        }
    ]

    collector = RDSCollector(mock_session, "ap-south-1")
    assets = await collector.collect()

    assert len(assets) == 1
    asset = assets[0]

    assert asset["asset_id"] == "prod-db-postgres-01"
    assert asset["provider"] == "aws"
    assert asset["type"] == "rds"
    assert asset["region"] == "ap-south-1"

    config = asset["configuration"]
    assert config["engine"] == "postgres"
    assert config["storage_encrypted"] is True
    assert config["multi_az"] is True
    assert config["publicly_accessible"] is False
    assert config["endpoint_port"] == 5432
    assert config["vpc_id"] == "vpc-0123456789abcdef0"
    assert config["tags"]["Environment"] == "Production"

    # Verify relationship linkages
    rel_types = [r["type"] for r in asset["relationships"]]
    assert "located_in" in rel_types
    assert "protected_by" in rel_types

    sg_rel = next(r for r in asset["relationships"] if r["type"] == "protected_by")
    assert sg_rel["target_id"] == "sg-0987654321fedcba0"
    assert sg_rel["target_type"] == "security_group"

    vpc_rel = next(r for r in asset["relationships"] if r["target_type"] == "vpc")
    assert vpc_rel["target_id"] == "vpc-0123456789abcdef0"


def test_orchestrator_initializes_rds():
    """Verify that ScanOrchestrator includes 'rds' in its registered collectors"""
    mock_session = MagicMock()
    orchestrator = ScanOrchestrator(cloud_account_id="fake-account", organization_id="fake-org")
    # Mock scan_job attribute
    mock_scan_job = MagicMock()
    mock_scan_job.region = "ap-south-1"
    orchestrator.scan_job = mock_scan_job

    collectors = orchestrator._initialize_collectors(mock_session)
    assert "rds" in collectors
    assert isinstance(collectors["rds"], RDSCollector)
    assert "ec2" in collectors
    assert "s3" in collectors
    assert "iam" in collectors
    assert "vpc" in collectors
    assert "security_groups" in collectors

