import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock

from security.engine.agent_controller import AgentEvent, EventSource, WorkerState, WorkerType
from security.engine.agent_workers import (
    AsyncQueueWorker, EventIngestionWorker, DetectionCorrelationWorker,
    ActivationRiskWorker, ResponseVerificationWorker
)

class ExplodingWorker(AsyncQueueWorker):
    def __init__(self):
        super().__init__("explode1", WorkerType.EVENT_INGESTION, "org1")
        
    async def process_event(self, event: AgentEvent):
        raise ValueError("Simulated unhandled exception processing event")

def create_event(event_id="e1", org_id="org1"):
    return AgentEvent(
        event_id=event_id,
        organization_id=org_id,
        event_type="CLOUD_EVENT",
        occurred_at=datetime.now(timezone.utc),
        source=EventSource.CLOUD,
        correlation_id="corr1",
        payload={"data": "test"}
    )

@pytest.mark.asyncio
async def test_worker_lifecycle():
    worker = EventIngestionWorker("w1", "org1")
    assert worker.state == WorkerState.CREATED
    
    await worker.start()
    assert worker.state == WorkerState.RUNNING
    assert worker._run_task is not None
    
    await worker.stop()
    assert worker.state == WorkerState.STOPPED
    assert worker._run_task.cancelled() or worker._run_task.done()

@pytest.mark.asyncio
async def test_worker_event_consumption():
    worker = DetectionCorrelationWorker("w2", "org1")
    await worker.start()
    
    e1 = create_event("e1")
    await worker.handle_event(e1)
    
    # Wait for the worker to process it
    await asyncio.sleep(0.05)
    
    assert worker.processed_count == 1
    assert worker.failed_count == 0
    
    await worker.stop()

@pytest.mark.asyncio
async def test_worker_backpressure():
    worker = ActivationRiskWorker("w3", "org1")
    worker.max_queue_size = 1 # Force strict bound
    await worker.start()
    
    # Pause the internal processing loop temporarily to force queue backup
    original_process = worker.process_event
    async def slow_process(e):
        await asyncio.sleep(0.5)
    worker.process_event = slow_process
    
    e1 = create_event("e1")
    e2 = create_event("e2")
    
    # Fill the queue
    await worker.handle_event(e1)
    
    # Queue is full, should raise exception rather than block the controller
    with pytest.raises(RuntimeError) as excinfo:
        await worker.handle_event(e2)
        
    assert "queue is full" in str(excinfo.value)
    
    await worker.stop()

@pytest.mark.asyncio
async def test_worker_isolation_on_malformed_event():
    worker = ExplodingWorker()
    await worker.start()
    
    e1 = create_event("e1")
    e2 = create_event("e2")
    
    await worker.handle_event(e1)
    await asyncio.sleep(0.05)
    
    # Worker should NOT have crashed the loop, it should just increment failed_count
    assert worker.state == WorkerState.RUNNING
    assert worker.failed_count == 1
    assert worker.processed_count == 0
    
    # It should still accept new events
    # We will override process_event back to normal to prove the loop is alive
    async def normal_process(e):
        pass
    worker.process_event = normal_process
    
    await worker.handle_event(e2)
    await asyncio.sleep(0.05)
    
    assert worker.processed_count == 1
    assert worker.state == WorkerState.RUNNING
    
    await worker.stop()

@pytest.mark.asyncio
async def test_worker_heartbeat_updates():
    worker = ResponseVerificationWorker("w4", "org1")
    await worker.start()
    
    initial_heartbeat = worker.last_heartbeat_at
    await asyncio.sleep(1.1) # Wait longer than timeout=1.0 in run loop
    
    # The run loop should hit TimeoutError and heartbeat
    assert worker.last_heartbeat_at > initial_heartbeat
    
    await worker.stop()
