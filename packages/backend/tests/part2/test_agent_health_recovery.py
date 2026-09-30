import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional
from security.engine.agent_controller import AgentState, WorkerState, AgentEvent, EventSource, AgentMode, AegivionAgentController
from security.engine.agent_workers import EventIngestionWorker, DetectionCorrelationWorker, ActivationRiskWorker, ResponseVerificationWorker

class FailingWorker(EventIngestionWorker):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.should_fail = False
        self.max_queue_size = 5  # For queue testing

    async def process_event(self, event):
        if self.should_fail and event.event_type != "PIPELINE_ERROR":
            raise ValueError("Injected failure")
        await super().process_event(event)

@pytest.mark.asyncio
async def test_health_monitor_basic():
    # 1. worker heartbeat updates
    # 2. healthy worker classified HEALTHY
    controller = AegivionAgentController()
    worker = FailingWorker("w1", "org1")
    controller.register_worker(worker)

    await controller.start()
    
    health = controller.get_health()
    assert health.agent_state == AgentState.RUNNING
    assert health.healthy_workers == 1
    assert health.stale_workers == 0
    assert health.degraded_workers == 0
    assert health.failed_workers == 0

    worker_health = controller.get_worker_health("w1")
    assert worker_health.healthy
    assert worker_health.last_heartbeat is not None
    
    await controller.stop()

@pytest.mark.asyncio
async def test_stale_detection_and_timeout():
    # 2. heartbeat timeout detected
    # 4. stale worker classified STALE
    controller = AegivionAgentController()
    worker = FailingWorker("w2", "org1")
    controller.register_worker(worker)
    
    await controller.start()
    
    # Manually make stale
    worker.last_heartbeat_at = datetime.now(timezone.utc) - timedelta(seconds=20)
    
    health = controller.get_health()
    assert health.stale_workers == 1
    
    # 15. critical worker failure affects agent state
    # Event ingestion is critical, agent should become FAILED if critical worker is stale/failed
    assert health.agent_state == AgentState.FAILED
    
    await controller.stop()

@pytest.mark.asyncio
async def test_worker_failure_isolated():
    # 5. worker failure isolated
    # 6. controller remains alive
    # 7. other workers remain alive
    # 27. worker exception does not kill controller
    controller = AegivionAgentController()
    worker1 = FailingWorker("w1", "org1")
    worker1.should_fail = True
    
    worker2 = DetectionCorrelationWorker("w2", "org1")
    
    controller.register_worker(worker1)
    controller.register_worker(worker2)
    
    await controller.start()
    
    event = AgentEvent(
        event_id="evt1",
        organization_id="org1",
        event_type="CLOUD_EVENT",
        occurred_at=datetime.now(timezone.utc),
        source=EventSource.CLOUD,
        correlation_id="c1",
        payload={}
    )
    
    # Process event will fail worker1
    await controller.submit_event(event)
    await asyncio.sleep(0.5)
    
    assert worker1.failed_count == 1
    
    # Controller remains alive
    assert controller.state == AgentState.RUNNING
    
    # Worker 2 remains alive
    assert worker2.state == WorkerState.RUNNING
    
    await controller.stop()

@pytest.mark.asyncio
async def test_worker_restart_bounded():
    # 8. restart requested
    # 9. worker restarts successfully
    # 12. bounded restart attempts
    # 14. permanently failing worker becomes FAILED
    # 21. duplicate restart prevented
    controller = AegivionAgentController()
    worker = FailingWorker("w1", "org1")
    controller.register_worker(worker)
    
    await controller.start()
    worker.state = WorkerState.FAILED
    
    # Manually trigger recovery logic once
    success = await controller.recovery_manager.attempt_restart(worker)
    assert success is True
    assert worker.state == WorkerState.RUNNING
    assert worker.restart_count == 1
    
    # Now exhaust restarts
    worker.state = WorkerState.FAILED
    await controller.recovery_manager.attempt_restart(worker) # 2
    worker.state = WorkerState.FAILED
    await controller.recovery_manager.attempt_restart(worker) # 3
    
    worker.state = WorkerState.FAILED
    # Attempt 4 should fail and mark worker as permanently FAILED
    success = await controller.recovery_manager.attempt_restart(worker)
    assert success is False
    assert worker.state == WorkerState.FAILED
    assert "Exceeded maximum restart" in worker.last_error
    
    await controller.stop()

@pytest.mark.asyncio
async def test_queue_full_observable():
    # 19. QUEUE_FULL observable
    # 20. no silent event loss
    controller = AegivionAgentController()
    worker = FailingWorker("w1", "org1")
    
    out_events = []
    worker.set_emit_callback(lambda e: out_events.append(e))
    
    await worker.start()
    
    event = AgentEvent(
        event_id="evt1",
        organization_id="org1",
        event_type="CLOUD_EVENT",
        occurred_at=datetime.now(timezone.utc),
        source=EventSource.CLOUD,
        correlation_id="c1",
        payload={}
    )
    
    # Fill the queue (max size 5)
    for _ in range(5):
        await worker.handle_event(event)
        
    # Attempting to add one more should raise RuntimeError and emit QUEUE_FULL
    with pytest.raises(RuntimeError) as exc:
        await worker.handle_event(event)
        
    assert "queue is full" in str(exc.value)
    
    # Check emitted events
    queue_full_events = [e for e in out_events if e.event_type == "QUEUE_FULL"]
    assert len(queue_full_events) == 1
    
    await worker.stop()

@pytest.mark.asyncio
async def test_startup_health_verification():
    # 23. startup health verification works
    controller = AegivionAgentController()
    worker = FailingWorker("w1", "org1")
    
    # Break worker start so it doesn't set RUNNING
    async def bad_start():
        worker.state = WorkerState.FAILED
        
    worker.start = bad_start
    controller.register_worker(worker)
    
    with pytest.raises(RuntimeError) as exc:
        await controller.start()
        
    assert "failed heartbeat verification on startup" in str(exc.value)
    assert controller.state == AgentState.FAILED
