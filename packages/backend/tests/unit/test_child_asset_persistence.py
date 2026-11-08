import pytest
import uuid
from app.cloud.aws.scan.orchestrator import ScanOrchestrator
from app.models.cloud import (
    CloudAsset,
    EC2InstanceAsset,
    S3BucketAsset,
    IAMUserAsset,
    SecurityGroupAsset
)
from app.models.cloud_account import CloudAccountV2
from app.models.organization import Organization
from app.database import SessionLocal

@pytest.mark.asyncio
async def test_persist_assets_populates_child_tables():
    """Verify that _persist_assets writes to parent CloudAsset AND specialized child tables with idempotency"""
    db = SessionLocal()
    org_id = uuid.uuid4()
    account_id = uuid.uuid4()
    slug = f"test-org-{uuid.uuid4().hex[:8]}"

    try:
        # Create valid Org with slug and commit first
        org = Organization(id=org_id, name="Test Child Tables Org", slug=slug)
        db.add(org)
        db.commit()

        # CloudAsset foreign keys to cloud_accounts_v2.id
        account_v2 = CloudAccountV2(
            id=account_id,
            account_id="123456789012",
            account_name="Test AWS Account V2",
            organization_id=org_id,
            provider="aws"
        )
        db.add(account_v2)
        db.commit()

        orchestrator = ScanOrchestrator(cloud_account_id=str(account_id), organization_id=str(org_id))
        orchestrator.db = db

        mock_assets = [
            {
                "asset_id": "i-0123456789abcdef0",
                "provider": "aws",
                "type": "ec2",
                "name": "web-server-01",
                "region": "ap-south-1",
                "configuration": {
                    "instance_type": "t3.micro",
                    "state": "running",
                    "public_ip": "13.235.12.34",
                    "private_ip": "10.0.1.15",
                    "security_groups": ["sg-12345"]
                }
            },
            {
                "asset_id": "aegivion-secure-logs-bucket",
                "provider": "aws",
                "type": "s3",
                "name": "aegivion-secure-logs-bucket",
                "region": "ap-south-1",
                "configuration": {
                    "bucket_name": "aegivion-secure-logs-bucket",
                    "arn": "arn:aws:s3:::aegivion-secure-logs-bucket",
                    "is_public": False,
                    "encryption_enabled": True,
                    "versioning_enabled": True
                }
            },
            {
                "asset_id": "arn:aws:iam::123456789012:user/developer-bob",
                "provider": "aws",
                "type": "iam",
                "name": "developer-bob",
                "region": "global",
                "configuration": {
                    "username": "developer-bob",
                    "arn": "arn:aws:iam::123456789012:user/developer-bob",
                    "mfa_enabled": True,
                    "is_admin": False,
                    "access_keys_age_days": 42
                }
            },
            {
                "asset_id": "sg-0987654321fedcba0",
                "provider": "aws",
                "type": "security_group",
                "name": "web-tier-sg",
                "region": "ap-south-1",
                "configuration": {
                    "group_id": "sg-0987654321fedcba0",
                    "group_name": "web-tier-sg",
                    "vpc_id": "vpc-12345",
                    "ingress_rules": [{"port": 443, "cidr": "0.0.0.0/0"}],
                    "egress_rules": []
                }
            }
        ]

        # 1. First Run: Should insert into parent and child tables
        count = await orchestrator._persist_assets(mock_assets)
        assert count == 4

        ec2_child = db.query(EC2InstanceAsset).filter_by(instance_id="i-0123456789abcdef0").first()
        assert ec2_child is not None
        assert ec2_child.instance_type == "t3.micro"
        assert ec2_child.public_ip == "13.235.12.34"
        assert ec2_child.has_public_ip is True

        s3_child = db.query(S3BucketAsset).filter_by(bucket_name="aegivion-secure-logs-bucket").first()
        assert s3_child is not None
        assert s3_child.encryption_enabled is True
        assert s3_child.is_public is False

        iam_child = db.query(IAMUserAsset).filter_by(username="developer-bob").first()
        assert iam_child is not None
        assert iam_child.mfa_enabled is True
        assert iam_child.access_keys_age_days == 42

        sg_child = db.query(SecurityGroupAsset).filter_by(group_id="sg-0987654321fedcba0").first()
        assert sg_child is not None
        assert sg_child.group_name == "web-tier-sg"
        assert len(sg_child.ingress_rules) == 1

        # 2. Second Run (Idempotency Check): Modifying an attribute and rerunning
        mock_assets[0]["configuration"]["instance_type"] = "t3.large"
        count_second = await orchestrator._persist_assets(mock_assets)
        assert count_second == 4

        # Verify updated in place without duplicate row creation
        ec2_children = db.query(EC2InstanceAsset).filter_by(instance_id="i-0123456789abcdef0").all()
        assert len(ec2_children) == 1
        assert ec2_children[0].instance_type == "t3.large"

    finally:
        # Cleanup
        try:
            db.query(EC2InstanceAsset).filter_by(instance_id="i-0123456789abcdef0").delete()
            db.query(S3BucketAsset).filter_by(bucket_name="aegivion-secure-logs-bucket").delete()
            db.query(IAMUserAsset).filter_by(username="developer-bob").delete()
            db.query(SecurityGroupAsset).filter_by(group_id="sg-0987654321fedcba0").delete()
            db.query(CloudAsset).filter_by(account_id=account_id).delete()
            db.query(CloudAccountV2).filter_by(id=account_id).delete()
            db.query(Organization).filter_by(id=org_id).delete()
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
