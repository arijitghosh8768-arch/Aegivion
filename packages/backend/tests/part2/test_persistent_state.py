import pytest
import asyncio
from datetime import datetime, timezone
import uuid

from security.models.persistent_state import (
    PersistentEvent, EventState,
    PersistentAgentState, PersistentWorkerState,
    PersistentDetectionContext, PersistentAttackState
)
from security.engine.persistence.memory import (
    InMemoryEventStore, InMemoryAgentStateRepository,
    InMemoryDetectionContextRepository, InMemoryAttackStateRepository
)
from security.engine.agent_controller import AegivionAgentController, WorkerType, AgentState, EventSource
from security.engine.agent_workers import AsyncQueueWorker

@pytest.mark.asyncio
async def test_persistent_event_store():
    store = InMemoryEventStore()
    
    # Add event
    event = PersistentEvent(
        event_id="e1",
        correlation_id="c1",
        org_id="org1",
        event_type="CLOUD_EVENT",
        payload={"data": "test"},
        source="CLOUD"
    )
    await store.add_event(event)
    
    # Claim event
    claimed = await store.claim_next_event("w1", ["CLOUD_EVENT"])
    assert claimed is not None
    assert claimed.event_id == "e1"
    assert claimed.status == EventState.CLAIMED
    assert claimed.claimed_by == "w1"
    assert claimed.fencing_token is not None
    
    # Update event state
    await store.update_event_state("org1", "e1", "w1", claimed.fencing_token, EventState.COMPLETED)
    
    completed = await store.get_event("org1", "e1")
    assert completed.status == EventState.COMPLETED

class MockPersistentWorker(AsyncQueueWorker):
    async def process_event(self, event):
        pass

@pytest.mark.asyncio
async def test_agent_controller_with_event_store():
    store = InMemoryEventStore()
    controller = AegivionAgentController(max_queue_size=10, organization_id="org1", event_store=store)
    
    worker = MockPersistentWorker("w1", WorkerType.EVENT_INGESTION, "org1")
    controller.register_worker(worker)
    
    await controller.start()
    
    from security.engine.agent_controller import AgentEvent
    event = AgentEvent(
        event_id="e1",
        organization_id="org1",
        event_type="CLOUD_EVENT",
        occurred_at=datetime.now(timezone.utc),
        source=EventSource.CLOUD,
        correlation_id="",
        payload={"data": "test"}
    )
    
    res = await controller.submit_event(event)
    assert res == "ACCEPTED"
    
    # The event should be in the store
    stored = await store.get_event("org1", "e1")
    assert stored is not None
    assert stored.event_type == "CLOUD_EVENT"
    
    # Since worker is running, it should claim it
    await asyncio.sleep(0.5)
    
    # Worker should have processed it and updated it to COMPLETED
    stored_final = await store.get_event("org1", "e1")
    assert stored_final.status == EventState.COMPLETED
    assert worker.processed_count == 1
    
    await controller.stop()
