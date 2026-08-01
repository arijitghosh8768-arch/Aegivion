import sys
import os
import asyncio
import uuid
from dotenv import load_dotenv

# Load root .env file
load_dotenv(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env")))

# Append packages directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import SessionLocal, engine, Base
from app.models.cloud import CloudAccount, ScanJob, ScanStatus
from app.cloud.aws.scan.orchestrator import ScanOrchestrator
from security.pipeline.detection_pipeline import DetectionPipeline
from app.api.v1.integration import start_scan, get_scan_status, get_dashboard_overview, ScanRequest

async def run_day14_tests():
    print("==================================================")
    print("Aegivion Day 14 End-to-End Orchestrator and Pipeline Tests")
    print("==================================================")

    # Initialize all database tables (including ScanJob and Relationship)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    # Create dummy account to test
    from app.models.organization import Organization
    org = db.query(Organization).first()
    if not org:
        org = Organization(id=uuid.uuid4(), name="Test Day 14 Org")
        db.add(org)
        db.commit()
    org_id = org.id

    dummy_id = uuid.uuid4()
    dummy_acc = CloudAccount(
        id=dummy_id,
        name="test-day14-account",
        aws_region="ap-south-1",
        organization_id=org_id
    )
    db.add(dummy_acc)
    db.commit()

    # 1. ScanOrchestrator start checks
    print("\n[Step 1] Verifying ScanOrchestrator background start...")
    orchestrator = ScanOrchestrator(
        cloud_account_id=str(dummy_id),
        organization_id=org_id
    )
    result = await orchestrator.start_scan()
    print(f"[OK] Scan job queued: {result['scan_id']}")
    assert result["status"] == "queued"

    # Wait briefly for queued background job task
    await asyncio.sleep(0.5)

    # 2. DetectionPipeline process verification
    print("\n[Step 2] Verifying DetectionPipeline execution and rule matches...")
    pipeline = DetectionPipeline()
    mock_assets = [
        {
            "asset_id": "s3:test-bucket",
            "provider": "aws",
            "type": "s3",
            "region": "ap-south-1",
            "name": "test-bucket",
            "configuration": {
                "public_access_block": {
                    "block_public_acls": False
                },
                "tags": {
                    "Environment": "production"
                }
            }
        }
    ]
    scan_id_str = result["scan_id"]
    pipeline_res = await pipeline.process_assets(scan_id_str, mock_assets)
    print(f"[OK] Pipeline completed.")
    print(f"     Assets processed: {pipeline_res.assets_processed}")
    print(f"     Findings generated: {pipeline_res.findings_generated}")
    print(f"     Findings updated: {pipeline_res.findings_updated}")
    assert pipeline_res.assets_processed == 1

    # 3. API Integrations verification
    print("\n[Step 3] Verifying Scan start FastAPI router handler...")
    request = ScanRequest(cloud_account_id=str(dummy_id))
    api_res = await start_scan(request, db)
    print(f"[OK] API start scan status: {api_res.status}")
    assert api_res.status == "queued"

    print("\n[Step 4] Verifying Scan status FastAPI router handler...")
    status_res = await get_scan_status(api_res.scan_id, db)
    print(f"[OK] Polled scan status: {status_res['status']}")
    assert status_res["status"] in ["queued", "running", "completed", "failed"]

    print("\n[Step 5] Verifying Dashboard Overview API metadata...")
    overview = await get_dashboard_overview(db)
    print(f"[OK] Overall risk: {overview['overall_risk']}")
    print(f"     Total assets discovered: {overview['total_assets']}")
    assert "overall_risk" in overview

    # Wait for background scans to complete/fail to avoid database constraint exceptions
    print("\nWaiting for background tasks to terminate...")
    await asyncio.sleep(2.0)

    # Cleanup test data
    db.query(ScanJob).filter_by(cloud_account_id=dummy_id).delete()
    db.query(CloudAccount).filter_by(id=dummy_id).delete()
    db.commit()

    print("\nAll Day 14 end-to-end integration tests PASSED successfully!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_day14_tests())
