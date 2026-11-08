import pytest
import uuid
import time
import hashlib
from datetime import datetime, timezone
from app.database import SessionLocal
from app.models.organization import Organization
from app.models.finding import Finding
from security.pipeline.detection_pipeline import DetectionPipeline

@pytest.mark.asyncio
async def test_detection_pipeline_sha256_fingerprint_and_occurrence_tracking():
    """
    Verify that DetectionPipeline:
    1. Generates SHA-256 fingerprint = sha256(org_id + ':' + rule_id + ':' + resource_id).
    2. Scan 1: Inserts new Finding with occurrence_count = 1 and status = 'open'.
    3. Scan 2: Finds record via fingerprint, updates last_seen, increments occurrence_count to 2, does NOT insert duplicate.
    4. Scan 3 (Reopen): If status was resolved, automatically reopens to 'open' and sets reopened_at.
    """
    db = SessionLocal()
    org_id = uuid.uuid4()
    slug = f"test-sha256-{uuid.uuid4().hex[:8]}"

    try:
        # 1. Create Organization in PostgreSQL
        org = Organization(id=org_id, name="Test SHA256 Intelligence Org", slug=slug)
        db.add(org)
        db.commit()

        resource_arn = "arn:aws:s3:::critical-leak-bucket-sha256"
        violating_asset = {
            "asset_id": resource_arn,
            "provider": "aws",
            "type": "s3",
            "name": "critical-leak-bucket-sha256",
            "region": "ap-south-1",
            "organization_id": str(org_id),
            "configuration": {
                "bucket_name": "critical-leak-bucket-sha256",
                "public_access": True,
                "is_public": True,
                "tags": {
                    "Environment": "Production",
                    "Criticality": "high"
                }
            }
        }

        pipeline = DetectionPipeline(db=db)

        # --- CYCLE 1: First Scan ---
        res1 = await pipeline.process_assets(
            scan_id=str(uuid.uuid4()),
            assets=[violating_asset],
            organization_id=str(org_id)
        )
        assert res1.findings_generated >= 1

        finding = db.query(Finding).filter_by(
            organization_id=org_id,
            resource_id=resource_arn
        ).first()

        assert finding is not None
        assert finding.fingerprint is not None
        expected_fingerprint = hashlib.sha256(f"{str(org_id)}:{finding.rule_id}:{resource_arn}".encode("utf-8")).hexdigest()
        assert finding.fingerprint == expected_fingerprint
        assert finding.occurrence_count == 1
        assert finding.status == "open"
        first_seen_initial = finding.first_seen

        time.sleep(0.1)

        # --- CYCLE 2: Second Scan (Same violation) ---
        res2 = await pipeline.process_assets(
            scan_id=str(uuid.uuid4()),
            assets=[violating_asset],
            organization_id=str(org_id)
        )
        assert res2.findings_generated == 0
        assert res2.findings_updated >= 1

        # Check occurrence_count incremented and only 1 row exists
        total_rows = db.query(Finding).filter_by(
            organization_id=org_id,
            resource_id=resource_arn
        ).count()
        assert total_rows == 1

        db.refresh(finding)
        assert finding.occurrence_count == 2
        assert finding.last_seen > first_seen_initial
        assert finding.first_seen == first_seen_initial

        # --- CYCLE 3: Reopen Previously Resolved Finding ---
        finding.status = "resolved"
        db.commit()

        res3 = await pipeline.process_assets(
            scan_id=str(uuid.uuid4()),
            assets=[violating_asset],
            organization_id=str(org_id)
        )

        db.refresh(finding)
        assert finding.status == "open"
        assert finding.occurrence_count == 3
        assert finding.reopened_at is not None

    finally:
        try:
            db.query(Finding).filter_by(organization_id=org_id).delete()
            db.query(Organization).filter_by(id=org_id).delete()
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
