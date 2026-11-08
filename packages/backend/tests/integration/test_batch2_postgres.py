import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.organization import Organization
from app.models.cloud_account import CloudAccountV2
from app.models.cloud import (
    CloudAsset,
    EC2InstanceAsset,
    S3BucketAsset,
    IAMUserAsset,
    SecurityGroupAsset,
    AssetRelationship,
    ScanJob
)
from app.repositories.asset_repository import AssetRepository
from app.repositories.cloud_account_repository import CloudAccountRepository

import os
from dotenv import load_dotenv, dotenv_values
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
test_env = dotenv_values(os.path.join(os.path.dirname(__file__), "..", "..", ".env.test"))

PG_URL = os.getenv("TEST_DATABASE_URL") or test_env.get("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
if PG_URL and PG_URL.startswith("postgresql://"):
    PG_URL = PG_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

@pytest.fixture(scope="module")
def pg_session():
    if not HAS_PSYCOPG2:
        pytest.skip("psycopg2 driver not installed in this environment")
    try:
        engine = create_engine(PG_URL)
        with engine.connect() as conn:
            pass
    except Exception as e:
        pytest.skip(f"PostgreSQL not reachable: {e}")

    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.rollback()
    session.close()

def test_cloud_account_v2_crud(pg_session):
    org = Organization(name="Cloud Org", slug=f"cloud-org-{uuid.uuid4().hex[:8]}")
    pg_session.add(org)
    pg_session.flush()

    acc = CloudAccountV2(
        organization_id=org.id,
        provider="aws",
        account_id="123456789012",
        account_name="Production AWS"
    )
    pg_session.add(acc)
    pg_session.commit()

    repo = CloudAccountRepository(pg_session)
    found = repo.get_by_id(acc.id)
    assert found is not None
    assert found.account_name == "Production AWS"

    by_org = repo.get_by_organization(org.id)
    assert len(by_org) == 1
    assert by_org[0].id == acc.id

    acc_id = str(acc.id)
    pg_session.delete(org)
    pg_session.commit()
    assert repo.get_by_id(acc_id) is None

def test_cloud_asset_crud_and_relationships(pg_session):
    org = Organization(name="Asset Org", slug=f"asset-org-{uuid.uuid4().hex[:8]}")
    pg_session.add(org)
    pg_session.flush()

    acc = CloudAccountV2(
        organization_id=org.id,
        provider="aws",
        account_id="999888777666",
        account_name="Asset AWS Account"
    )
    pg_session.add(acc)
    pg_session.flush()

    # Cloud Asset
    asset = CloudAsset(
        account_id=acc.id,
        resource_id="i-0abcdef1234567890",
        name="web-server-prod",
        type="AWS::EC2::Instance",
        region="ap-south-1",
        provider="AWS"
    )
    pg_session.add(asset)
    pg_session.flush()

    # Child detail: EC2InstanceAsset
    ec2_detail = EC2InstanceAsset(
        asset_id=asset.id,
        instance_id="i-0abcdef1234567890",
        state="running",
        public_ip="13.232.1.2",
        instance_type="t3.medium",
        has_public_ip=True
    )
    pg_session.add(ec2_detail)
    pg_session.commit()

    # Query via AssetRepository
    asset_repo = AssetRepository(pg_session)
    org_assets = asset_repo.get_by_organization(str(org.id))
    assert len(org_assets) == 1
    assert org_assets[0].resource_id == "i-0abcdef1234567890"

    queried_asset = asset_repo.get_by_organization_and_id(str(org.id), str(asset.id))
    assert queried_asset is not None
    assert queried_asset.ec2_instance_details is not None
    assert queried_asset.ec2_instance_details.public_ip == "13.232.1.2"

    # Cleanup
    asset_id = str(asset.id)
    ec2_id = str(ec2_detail.id)
    pg_session.delete(org)
    pg_session.commit()
    assert pg_session.query(CloudAsset).filter(CloudAsset.id == asset_id).first() is None
    assert pg_session.query(EC2InstanceAsset).filter(EC2InstanceAsset.id == ec2_id).first() is None

def test_asset_relationships_crud(pg_session):
    org = Organization(name="Rel Org", slug=f"rel-org-{uuid.uuid4().hex[:8]}")
    pg_session.add(org)
    pg_session.flush()

    rel = AssetRelationship(
        organization_id=org.id,
        source_asset_id="arn:aws:iam::123:role/AdminRole",
        target_asset_id="arn:aws:s3:::sensitive-bucket",
        relationship_type="CAN_ACCESS",
        confidence="HIGH"
    )
    pg_session.add(rel)
    pg_session.commit()

    found_rel = pg_session.query(AssetRelationship).filter(
        AssetRelationship.organization_id == org.id,
        AssetRelationship.relationship_type == "CAN_ACCESS"
    ).first()
    assert found_rel is not None
    assert found_rel.target_asset_id == "arn:aws:s3:::sensitive-bucket"

    rel_id = rel.id
    pg_session.delete(org)
    pg_session.commit()
    assert pg_session.query(AssetRelationship).filter(AssetRelationship.id == rel_id).first() is None

def test_tenant_isolation_on_assets(pg_session):
    # Org A
    org_a = Organization(name="Asset Tenant A", slug=f"ast-a-{uuid.uuid4().hex[:8]}")
    pg_session.add(org_a)
    pg_session.flush()
    acc_a = CloudAccountV2(organization_id=org_a.id, provider="aws", account_id="111111111111")
    pg_session.add(acc_a)
    pg_session.flush()
    asset_a = CloudAsset(account_id=acc_a.id, resource_id="res-a", name="Asset A", type="AWS::S3::Bucket")
    pg_session.add(asset_a)

    # Org B
    org_b = Organization(name="Asset Tenant B", slug=f"ast-b-{uuid.uuid4().hex[:8]}")
    pg_session.add(org_b)
    pg_session.flush()
    acc_b = CloudAccountV2(organization_id=org_b.id, provider="aws", account_id="222222222222")
    pg_session.add(acc_b)
    pg_session.flush()
    asset_b = CloudAsset(account_id=acc_b.id, resource_id="res-b", name="Asset B", type="AWS::S3::Bucket")
    pg_session.add(asset_b)
    pg_session.commit()

    repo = AssetRepository(pg_session)
    assets_for_a = repo.get_by_organization(str(org_a.id))
    assert len(assets_for_a) == 1
    assert assets_for_a[0].id == asset_a.id

    # Cross-tenant direct access denial
    assert repo.get_by_organization_and_id(str(org_a.id), str(asset_b.id)) is None

    # Cleanup
    pg_session.delete(org_a)
    pg_session.delete(org_b)
    pg_session.commit()
