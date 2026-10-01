import time
import uuid
import logging
from datetime import datetime
from typing import Dict, Any
from app.database import SessionLocal
from app.database.supabase_client import supabase
from app.services.security_event_ingestion_service import SecurityEventIngestionService
from app.aws.client import get_aws_session
import json
import asyncio

logger = logging.getLogger(__name__)

class CloudTrailWorker:
    """
    24/7 continuous ingestion worker for AWS CloudTrail.
    Supports idempotent processing, graceful shutdown, and heartbeat reporting.
    """
    
    def __init__(self, organization_id: str, account_id: str, queue_url: str):
        self.worker_id = str(uuid.uuid4())
        self.organization_id = organization_id
        self.account_id = account_id
        self.queue_url = queue_url
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
        # 1. Poll real AWS events via SQS
        session = get_aws_session()
        if not session:
            logger.error("Failed to acquire AWS session for CloudTrail polling")
            self.status = "DEGRADED"
            return

        sqs = session.client('sqs')
        
        try:
            response = sqs.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=10,
                MessageAttributeNames=['All']
            )
        except Exception as e:
            logger.error(f"Failed to receive messages from SQS: {str(e)}")
            raise e

        messages = response.get('Messages', [])
        if not messages:
            return
            
        db_session = SessionLocal()
        ingestion_service = SecurityEventIngestionService(supabase, db_session)
        
        context = {
            "organization_id": self.organization_id,
            "account_id": self.account_id,
            "provider": "aws"
        }
        
        for msg in messages:
            try:
                body = json.loads(msg['Body'])
                
                # If this is an EventBridge event, the CloudTrail payload is in 'detail'
                raw_event = body.get('detail', body)
                
                # In asyncio loop contexts we'd use await, but since this worker uses time.sleep, 
                # we'll assume a sync context for the worker loop or run ingestion in a loop.
                # SecurityEventIngestionService.ingest is async!
                result = asyncio.run(ingestion_service.ingest(raw_event, context))
                
                if result["status"] in ("stored", "duplicate"):
                    if result["status"] == "stored":
                        self.events_processed += 1
                        self.last_success = datetime.utcnow()
                        self.status = "HEALTHY"
                    else:
                        self.events_duplicate += 1
                        
                    # Delete the message on success or duplicate
                    sqs.delete_message(
                        QueueUrl=self.queue_url,
                        ReceiptHandle=msg['ReceiptHandle']
                    )
                else:
                    self.events_rejected += 1
                    logger.warning(f"Event rejected: {result.get('reason')}")
                    
            except Exception as e:
                self.events_rejected += 1
                logger.error(f"Failed to process SQS message: {str(e)}")
                # We do not delete the message so it goes to DLQ
                
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
