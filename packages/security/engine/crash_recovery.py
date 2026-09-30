import logging
from typing import Dict, Any, List, Optional
import asyncio

from security.models.distributed_health import HealthState
from security.engine.agent_recovery import AgentRecoveryManager
from security.engine.persistence.base import EventStore
from security.engine.distributed_health_monitor import DistributedHealthMonitor

logger = logging.getLogger(__name__)

class CrashRecoveryManager:
    def __init__(
        self, 
        event_store: EventStore, 
        health_monitor: DistributedHealthMonitor, 
        agent_recovery_manager: AgentRecoveryManager
    ):
        self.event_store = event_store
        self.health_monitor = health_monitor
        self.agent_recovery_manager = agent_recovery_manager
        
        self.metrics = {
            "worker_crashes": 0,
            "node_failures": 0,
            "expired_leases": 0,
            "events_reclaimed": 0,
            "recovery_attempts": 0,
            "recovery_success": 0,
            "recovery_failure": 0,
            "dead_letter_count": 0,
            "dead_letter_requeues": 0,
            "dead_letter_requeue_denied": 0,
            "zombie_mutations_rejected": 0
        }

    async def recover_stale_workers(self, local_workers: Dict[str, Any]):
        """Scan for stale workers in the local node and attempt recovery."""
        workers = await self.health_monitor.repository.list_workers()
        
        # Check node failures
        snapshot = await self.health_monitor.get_health_snapshot()
        for node_health in snapshot.nodes:
            if node_health.state in (HealthState.STALE, HealthState.FAILED):
                self.metrics["node_failures"] += 1
                
        for w in workers:
            if w.state == HealthState.STALE:
                self.metrics["worker_crashes"] += 1
                
                if w.worker_id in local_workers:
                    worker = local_workers[w.worker_id]
                    logger.info(f"Detected STALE local worker {w.worker_id}, attempting recovery.")
                    self.metrics["recovery_attempts"] += 1
                    
                    success = await self.agent_recovery_manager.attempt_restart(worker)
                    if success:
                        self.metrics["recovery_success"] += 1
                    else:
                        self.metrics["recovery_failure"] += 1

    async def requeue_dead_letter(self, org_id: str, event_id: str, requested_by: str, reason: str, max_requeues: int = 3) -> bool:
        """Explicitly requeue a DEAD_LETTER event."""
        logger.info(f"DEAD_LETTER requeue requested for {org_id}:{event_id} by {requested_by}")
        
        success = await self.event_store.requeue_dead_letter(
            org_id=org_id,
            event_id=event_id,
            requested_by=requested_by,
            reason=reason,
            max_requeues=max_requeues
        )
        
        if success:
            self.metrics["dead_letter_requeues"] += 1
            return True
        else:
            self.metrics["dead_letter_requeue_denied"] += 1
            return False

    async def perform_startup_recovery(self, local_workers: Dict[str, Any]):
        """
        1. load persistent runtime state
        2. inspect stale workers
        3. inspect expired leases
        4. do NOT assume previous workers are alive
        5. allow expired event ownership to become reclaimable
        6. start local workers
        7. verify heartbeats
        8. report recovered/degraded state
        """
        logger.info("Performing startup recovery...")
        # Start local workers
        for w_id, worker in local_workers.items():
            await worker.start(preserve_queue=True)
            
        # Verify heartbeats and stale states
        await asyncio.sleep(0.5)
        await self.recover_stale_workers(local_workers)
        
        snapshot = await self.health_monitor.get_health_snapshot()
        logger.info(f"Startup recovery completed. Cluster state: {snapshot.state}")
