import logging
import asyncio
from datetime import datetime, timezone
from security.engine.agent_controller import WorkerState
from security.engine.agent_health import WorkerHealth, AgentHealthMonitor

logger = logging.getLogger(__name__)

class AgentRecoveryManager:
    def __init__(self, max_restart_attempts: int = 3, restart_backoff_seconds: int = 1, maximum_backoff_seconds: int = 30):
        self.max_restart_attempts = max_restart_attempts
        self.restart_backoff_seconds = restart_backoff_seconds
        self.maximum_backoff_seconds = maximum_backoff_seconds
        self.health_monitor = AgentHealthMonitor()

    async def attempt_restart(self, worker) -> bool:
        """Attempts to safely restart a worker, applying bounded backoff and circuit breaker."""
        # Circuit breaker
        if worker.restart_count >= self.max_restart_attempts:
            worker.state = WorkerState.FAILED
            worker.last_error = f"Exceeded maximum restart attempts ({self.max_restart_attempts})"
            worker.last_error_at = datetime.now(timezone.utc)
            logger.error(f"Worker {worker.worker_id} exceeded max restarts. Permanently FAILED.")
            return False

        # Calculate backoff
        backoff = min(self.restart_backoff_seconds * (2 ** worker.restart_count), self.maximum_backoff_seconds)
        logger.info(f"Attempting to restart worker {worker.worker_id} in {backoff} seconds (Attempt {worker.restart_count + 1}/{self.max_restart_attempts})")
        
        # Bounded backoff wait
        await asyncio.sleep(backoff)
        
        # Increment restart counter
        worker.restart_count += 1
        
        # Safe restart sequence
        try:
            await worker.stop()  # Ensure it is stopped fully
            
            # Reset runtime state, but preserve queues if possible
            # Depending on queue semantics, we may just leave the queue intact.
            # We call start() which will re-initialize run task. 
            # In start(), if we recreate the queue we lose events. We should modify worker.start() to preserve queue if it exists.
            
            await worker.start(preserve_queue=True)
            
            # Verify health
            # Give it a moment to heartbeat
            await asyncio.sleep(0.5)
            health = worker.get_health()
            if health.state == WorkerState.RUNNING and health.healthy:
                logger.info(f"Worker {worker.worker_id} restarted successfully.")
                return True
            else:
                logger.warning(f"Worker {worker.worker_id} restart verification failed. State: {health.state}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to restart worker {worker.worker_id}: {e}")
            worker.state = WorkerState.FAILED
            worker.last_error = str(e)
            worker.last_error_at = datetime.now(timezone.utc)
            return False
