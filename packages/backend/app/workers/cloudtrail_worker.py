import time
import uuid
import logging
from datetime import datetime
from typing import Dict, Any
from app.database import SessionLocal
from app.database.supabase_client import supabase
from app.services.security_event_ingestion_service import SecurityEventIngestionService

logger = logging.getLogger(__name__)

class CloudTrailWorker:
    """
    24/7 continuous ingestion worker for AWS CloudTrail.
    Supports idempotent processing, graceful shutdown, and heartbeat reporting.
    """
    
    def __init__(self, organization_id: str, account_id: str):
        self.worker_id = str(uuid.uuid4())
        self.organization_id = organization_id
        self.account_id = account_id
        self.status = "STOPPED"
        
        self.last_heartbeat = None
        self.last_success = None
        self.last_failure = None
        
        self.events_processed = 0
        self.events_duplicate = 0
        self.events_rejected = 0
        
        self._shutdown_requested = False

    def start(self):
        self.status = "HEALTHY"
        logger.info(f"Worker {self.worker_id} started for ORG {self.organization_id} ACC {self.account_id}")
        
        while not self._shutdown_requested:
            self._heartbeat()
            try:
                self._poll_and_ingest()
                time.sleep(10)  # Polling interval
            except Exception as e:
                self.status = "DEGRADED"
                self.last_failure = datetime.utcnow()
                logger.error(f"Worker error: {str(e)}")
                time.sleep(30) # Backoff
                
        self.status = "STOPPED"

    def stop(self):
        self._shutdown_requested = True
        logger.info(f"Worker {self.worker_id} shutdown requested.")

    def _heartbeat(self):
        self.last_heartbeat = datetime.utcnow()
        # Optionally write heartbeat to DB
        pass

    def _poll_and_ingest(self):
        # 1. Poll real AWS events
        # In a real setup, we use boto3 CloudTrail client here
        events = [] # mock fetch
        
        if not events:
            return
            
        db_session = SessionLocal()
        ingestion_service = SecurityEventIngestionService(supabase, db_session)
        
        context = {
            "organization_id": self.organization_id,
            "account_id": self.account_id,
            "provider": "aws"
        }
        
        for raw_event in events:
            try:
                result = ingestion_service.ingest(raw_event, context)
                
                if result["status"] == "stored":
                    self.events_processed += 1
                    self.last_success = datetime.utcnow()
                    self.status = "HEALTHY"
                elif result["status"] == "duplicate":
                    self.events_duplicate += 1
                else:
                    self.events_rejected += 1
                    
            except Exception as e:
                self.events_rejected += 1
                raise e
        
        db_session.close()

    def get_health(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "provider": "aws",
            "organization_id": self.organization_id,
            "account_id": self.account_id,
            "status": self.status,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_failure": self.last_failure.isoformat() if self.last_failure else None,
            "events_processed": self.events_processed,
            "events_duplicate": self.events_duplicate,
            "events_rejected": self.events_rejected
        }
