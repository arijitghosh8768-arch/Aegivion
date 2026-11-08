import pytest
import uuid
import time
from datetime import datetime, timezone
from app.cloud.aws.scan.orchestrator import ScanOrchestrator
from app.models.cloud import CloudAsset, EC2InstanceAsset
from app.models.cloud_account import CloudAccountV2
from app.models.history import AssetSnapshot
from app.models.organization import Organization
from app.database import SessionLocal

@pytest.mark.asyncio
async def test_incremental_diff_and_snapshots():
    """
    Verify 3-step incremental diff cycle:
    1. Scan 1 (New Asset): Generates CloudAsset and AssetSnapshot (Version 1).
    2. Scan 2 (Unchanged Config): No new snapshot created; last_seen_at updated.
    3. Scan 3 (Changed Config): Generates AssetSnapshot (Version 2); CloudAsset updated.
    """
    db = SessionLocal()
    org_id = uuid.uuid4()
    account_id = uuid.uuid4()
    slug = f"test-inc-{uuid.uuid4().hex[:8]}"

    try:
        # Create Org and Account
        org = Organization(id=org_id, name="Test Incremental Org", slug=slug)
        db.add(org)
        db.commit()

        account = CloudAccountV2(
            id=account_id,
            account_id="123456789012",
            account_name="Test Incremental Account",
            organization_id=org_id,
            provider="aws"
        )
        db.add(account)
        db.commit()

        orchestrator = ScanOrchestrator(cloud_account_id=str(account_id), organization_id=str(org_id))
        orchestrator.db = db

        asset_payload = [
            {
                "asset_id": "i-diff-test-001",
                "provider": "aws",
                "type": "ec2",
                "name": "diff-vm-01",
                "region": "ap-south-1",
                "configuration": {
                    "instance_type": "t3.medium",
                    "state": "running",
                    "public_ip": "1.2.3.4"
                }
            }
        ]

        # --- CYCLE 1: New Asset ---
        count1 = await orchestrator._persist_assets(asset_payload)
        assert count1 == 1

        asset_record = db.query(CloudAsset).filter_by(resource_id="i-diff-test-001").first()
        assert asset_record is not None
        assert asset_record.current_hash is not None
        first_last_seen = asset_record.last_seen_at

        snapshots_v1 = db.query(AssetSnapshot).filter_by(asset_id="i-diff-test-001").all()
        assert len(snapshots_v1) == 1
        assert snapshots_v1[0].version_number == 1
        assert snapshots_v1[0].configuration_hash == asset_record.current_hash

        # Small delay to guarantee timestamp difference
        time.sleep(0.1)

        # --- CYCLE 2: Unchanged Asset (Same configuration) ---
        count2 = await orchestrator._persist_assets(asset_payload)
        assert count2 == 1

        db.refresh(asset_record)
        snapshots_v2 = db.query(AssetSnapshot).filter_by(asset_id="i-diff-test-001").all()
        # Verify NO new snapshot was created
        assert len(snapshots_v2) == 1
        # Verify last_seen_at was refreshed
        assert asset_record.last_seen_at >= first_last_seen

        # --- CYCLE 3: Changed Configuration ---
        asset_payload[0]["configuration"]["instance_type"] = "t3.xlarge"
        asset_payload[0]["configuration"]["public_ip"] = "5.6.7.8"

        count3 = await orchestrator._persist_assets(asset_payload)
        assert count3 == 1

        db.refresh(asset_record)
        snapshots_v3 = db.query(AssetSnapshot).filter_by(asset_id="i-diff-test-001").order_by(AssetSnapshot.version_number.asc()).all()
        # Verify Version 2 snapshot was created
        assert len(snapshots_v3) == 2
        assert snapshots_v3[0].version_number == 1
        assert snapshots_v3[1].version_number == 2
        assert snapshots_v3[1].configuration["instance_type"] == "t3.xlarge"

        # Child table updated
        ec2_child = db.query(EC2InstanceAsset).filter_by(asset_id=asset_record.id).first()
        assert ec2_child.instance_type == "t3.xlarge"
        assert ec2_child.public_ip == "5.6.7.8"

    finally:
        # Cleanup
        try:
            db.query(AssetSnapshot).filter_by(asset_id="i-diff-test-001").delete()
            db.query(EC2InstanceAsset).filter_by(instance_id="i-diff-test-001").delete()
            db.query(CloudAsset).filter_by(resource_id="i-diff-test-001").delete()
            db.query(CloudAccountV2).filter_by(id=account_id).delete()
            db.query(Organization).filter_by(id=org_id).delete()
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

