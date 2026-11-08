import asyncio
import uuid
from datetime import datetime, timedelta, timezone
import logging
import os
import sys

app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

from app.database.session import SessionLocal
from app.models.automation import AgentHeartbeat, ResponseExecution, PendingApproval
from app.models.cloud import CloudAccount, ScanJob, ScanStatus
from app.cloud.aws.scan.orchestrator import ScanOrchestrator
from app.core.websocket import ws_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("automation_worker")

# Periodic AWS sync interval in hours (default: 6 hours)
PERIODIC_SYNC_INTERVAL_HOURS = int(os.getenv("PERIODIC_SYNC_INTERVAL_HOURS", "6"))

async def run_periodic_aws_discovery(db, organization_id=None):
    """
    Checks active AWS cloud accounts and triggers a background ScanJob
    if no scan is currently active (QUEUED or RUNNING) and last_scan_at is older than interval.
    If organization_id is provided, only inspects accounts within that organization.
    """
    try:
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=PERIODIC_SYNC_INTERVAL_HOURS)

        query = db.query(CloudAccount).filter(
            CloudAccount.provider == "AWS",
            CloudAccount.status.in_(["connected", "HEALTHY"])
        )
        if organization_id:
            query = query.filter(CloudAccount.organization_id == organization_id)

        accounts = query.all()

        for account in accounts:
            # Check if there is an active scan in progress for this cloud account
            active_scan = db.query(ScanJob).filter(
                ScanJob.cloud_account_id == account.id,
                ScanJob.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING, "queued", "running"])
            ).first()

            if active_scan:
                logger.info(f"Skipping periodic scan for account {account.id}; scan {active_scan.id} is {active_scan.status}")
                continue

            # Check if last_scan_at is older than cutoff or never scanned
            last_scan = account.last_scan_at
            if last_scan and last_scan.tzinfo is None:
                last_scan = last_scan.replace(tzinfo=timezone.utc)

            if not last_scan or last_scan <= cutoff_time:
                logger.info(f"Triggering scheduled AWS discovery scan for account {account.id} (last_scan: {last_scan})")
                orchestrator = ScanOrchestrator(
                    cloud_account_id=str(account.id),
                    organization_id=str(account.organization_id)
                )
                await orchestrator.start_scan()
                account.last_scan_at = now
                db.add(account)

        db.commit()
    except Exception as e:
        logger.error(f"Error during periodic AWS discovery check: {e}")
        db.rollback()

async def automation_worker_loop():
    logger.info("Starting Master Automation Worker Loop with Resilient Periodic AWS Sync...")
    db = SessionLocal()
    try:
        # Initialize mock agent heartbeats if none exist
        workers = ["discovery", "remediation", "threat-intel"]
        for w in workers:
            hb = db.query(AgentHeartbeat).filter_by(worker=w).first()
            if not hb:
                hb = AgentHeartbeat(
                    id=uuid.uuid4(),
                    worker=w,
                    status="RUNNING",
                    current_activity="Initializing...",
                    organization_id=uuid.uuid4()
                )
                db.add(hb)
        db.commit()
    except Exception as e:
        logger.error(f"Error initializing automation worker: {e}")
        db.rollback()
    finally:
        db.close()

    last_periodic_check = datetime.min.replace(tzinfo=timezone.utc)

    while True:
        db = SessionLocal()
        try:
            logger.info("Automation Worker tick...")
            now = datetime.now(timezone.utc)

            # 1. Update Heartbeats
            heartbeats = db.query(AgentHeartbeat).all()
            for hb in heartbeats:
                hb.last_heartbeat = now.isoformat()
                
                # Rotate activities for visual effect in UI
                sec = now.second
                if hb.worker == "discovery":
                    hb.current_activity = "Scanning AWS US-East-1" if sec % 10 < 5 else "Idle"
                elif hb.worker == "remediation":
                    hb.current_activity = "Awaiting approval..."
                elif hb.worker == "threat-intel":
                    hb.current_activity = "Syncing CISA feeds..."
                    
                db.add(hb)
                
            # 2. Process ResponseExecutions
            executions = db.query(ResponseExecution).filter_by(status="QUEUED").all()
            for exec_item in executions:
                logger.info(f"Picking up queued execution: {exec_item.id}")
                exec_item.status = "RUNNING"
                db.add(exec_item)
                
            # Move RUNNING to COMPLETED
            running = db.query(ResponseExecution).filter_by(status="RUNNING").all()
            for exec_item in running:
                raw_created = getattr(exec_item, "created_at", None)
                if isinstance(raw_created, datetime):
                    created = raw_created
                elif isinstance(raw_created, str):
                    try:
                        created = datetime.fromisoformat(raw_created)
                    except Exception:
                        created = now
                else:
                    created = now

                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                if now > created + timedelta(seconds=10):
                    logger.info(f"Completing execution: {exec_item.id}")
                    exec_item.status = "COMPLETED"
                    exec_item.completed_at = now.isoformat()
                    exec_item.verification_status = "SUCCESS"
                    db.add(exec_item)

            db.commit()

            # 3. Periodic AWS Cloud Discovery (Checks every 60 seconds)
            if now - last_periodic_check > timedelta(seconds=60):
                await run_periodic_aws_discovery(db)
                last_periodic_check = now
            
            # Broadcast update to UI connected via WS
            await ws_manager.broadcast("automation_update")
            
        except Exception as e:
            logger.error(f"Error in automation worker: {e}")
            db.rollback()
        finally:
            db.close()
            
        await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(automation_worker_loop())
