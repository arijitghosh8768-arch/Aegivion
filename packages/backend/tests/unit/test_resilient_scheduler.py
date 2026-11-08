import pytest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from botocore.config import Config

from app.cloud.aws.client import AWS_CLIENT_CONFIG, get_aws_session as get_cloud_aws_session
from app.aws.client import AWS_CLIENT_CONFIG as BASE_AWS_CLIENT_CONFIG
from app.workers.automation_worker import run_periodic_aws_discovery
from app.models.cloud import CloudAccount, ScanJob, ScanStatus
from app.models.organization import Organization
from app.database import SessionLocal

def test_botocore_adaptive_retry_config():
    """Verify that AWS_CLIENT_CONFIG specifies adaptive retries with 5 attempts"""
    assert isinstance(AWS_CLIENT_CONFIG, Config)
    retries = getattr(AWS_CLIENT_CONFIG, "retries", None) or getattr(AWS_CLIENT_CONFIG, "_user_provided_options", {}).get("retries", {})
    max_attempts = retries.get("max_attempts") if isinstance(retries, dict) else getattr(retries, "max_attempts", None)
    mode = retries.get("mode") if isinstance(retries, dict) else getattr(retries, "mode", None)
    assert max_attempts == 5
    assert mode == "adaptive"

    assert isinstance(BASE_AWS_CLIENT_CONFIG, Config)
    base_retries = getattr(BASE_AWS_CLIENT_CONFIG, "retries", None) or getattr(BASE_AWS_CLIENT_CONFIG, "_user_provided_options", {}).get("retries", {})
    base_max_attempts = base_retries.get("max_attempts") if isinstance(base_retries, dict) else getattr(base_retries, "max_attempts", None)
    base_mode = base_retries.get("mode") if isinstance(base_retries, dict) else getattr(base_retries, "mode", None)
    assert base_max_attempts == 5
    assert base_mode == "adaptive"

@pytest.mark.asyncio
async def test_periodic_aws_discovery_skips_running_scans():
    """Verify run_periodic_aws_discovery does not schedule duplicate scans if one is currently active"""
    db = SessionLocal()
    org_id = uuid.uuid4()
    account_id = uuid.uuid4()
    slug = f"test-periodic-{uuid.uuid4().hex[:8]}"

    try:
        org = Organization(id=org_id, name="Test Periodic Org", slug=slug)
        db.add(org)
        db.commit()

        # Account whose last scan is overdue (10 hours ago)
        overdue_time = datetime.now(timezone.utc) - timedelta(hours=10)
        account = CloudAccount(
            id=account_id,
            name="Test Overdue Account",
            organization_id=org_id,
            provider="AWS",
            status="connected",
            last_scan_at=overdue_time
        )
        db.add(account)

        # Existing active scan job in RUNNING state
        scan_job = ScanJob(
            id=uuid.uuid4(),
            cloud_account_id=account_id,
            organization_id=org_id,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc)
        )
        db.add(scan_job)
        db.commit()

        with patch("app.cloud.aws.scan.orchestrator.ScanOrchestrator.start_scan") as mock_start_scan:
            await run_periodic_aws_discovery(db, organization_id=org_id)
            # Should NOT start another scan because scan_job is RUNNING
            mock_start_scan.assert_not_called()

    finally:
        try:
            db.query(ScanJob).filter_by(cloud_account_id=account_id).delete()
            db.query(CloudAccount).filter_by(id=account_id).delete()
            db.query(Organization).filter_by(id=org_id).delete()
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

@pytest.mark.asyncio
async def test_periodic_aws_discovery_triggers_overdue_scan():
    """Verify run_periodic_aws_discovery triggers scan when account is overdue and idle"""
    db = SessionLocal()
    org_id = uuid.uuid4()
    account_id = uuid.uuid4()
    slug = f"test-periodic-idle-{uuid.uuid4().hex[:8]}"

    try:
        org = Organization(id=org_id, name="Test Periodic Idle Org", slug=slug)
        db.add(org)
        db.commit()

        overdue_time = datetime.now(timezone.utc) - timedelta(hours=8)
        account = CloudAccount(
            id=account_id,
            name="Test Idle Account",
            organization_id=org_id,
            provider="AWS",
            status="connected",
            last_scan_at=overdue_time
        )
        db.add(account)
        db.commit()

        with patch("app.cloud.aws.scan.orchestrator.ScanOrchestrator.start_scan") as mock_start_scan:
            await run_periodic_aws_discovery(db, organization_id=org_id)
            # Should start a scan
            mock_start_scan.assert_called_once()

    finally:
        try:
            db.query(CloudAccount).filter_by(id=account_id).delete()
            db.query(Organization).filter_by(id=org_id).delete()
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

