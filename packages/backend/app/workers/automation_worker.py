import asyncio
import uuid
from datetime import datetime, timedelta
import logging

import os
import sys

app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

from app.database import MongoSQLSession, db as mongo_db
from app.models.automation import AgentHeartbeat, ResponseExecution, PendingApproval
from app.core.websocket import ws_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("automation_worker")

async def automation_worker_loop():
    logger.info("Starting Master Automation Worker Loop...")
    db = MongoSQLSession(mongo_db)
    
    # Initialize some mock agent heartbeats if none exist
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

    while True:
        try:
            logger.info("Automation Worker tick...")
            db = MongoSQLSession(mongo_db)
            
            # 1. Update Heartbeats
            heartbeats = db.query(AgentHeartbeat).all()
            for hb in heartbeats:
                hb.last_heartbeat = datetime.utcnow().isoformat()
                
                # Rotate activities for visual effect in UI
                if hb.worker == "discovery":
                    hb.current_activity = "Scanning AWS US-East-1" if datetime.utcnow().second % 10 < 5 else "Idle"
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
                # Mock a 10 second run time
                created = datetime.fromisoformat(exec_item.created_at)
                if datetime.utcnow() > created + timedelta(seconds=10):
                    logger.info(f"Completing execution: {exec_item.id}")
                    exec_item.status = "COMPLETED"
                    exec_item.completed_at = datetime.utcnow().isoformat()
                    exec_item.verification_status = "SUCCESS"
                    db.add(exec_item)

            db.commit()
            
            # Broadcast update to UI connected via WS
            await ws_manager.broadcast("automation_update")
            
        except Exception as e:
            logger.error(f"Error in automation worker: {e}")
            
        await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(automation_worker_loop())
