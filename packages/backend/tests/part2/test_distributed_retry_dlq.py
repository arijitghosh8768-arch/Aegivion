import asyncio
import pytest
from datetime import datetime, timezone

from security.models.persistent_state import PersistentEvent, EventState
from security.engine.persistence.memory import InMemoryEventStore
from security.engine.agent_workers import WorkerValidationError, WorkerTransientError, AsyncQueueWorker
from security.engine.agent_controller import WorkerType, AgentEvent, EventSource

class MockRetryWorker(AsyncQueueWorker):
    def __init__(self, worker_id: str, org_id: str, store: InMemoryEventStore):
        super().__init__(worker_id, WorkerType.EVENT_INGESTION, org_id)
        self.event_store = store
        self.should_fail_with = None
        
    async def process_event(self, event: AgentEvent):
        if self.should_fail_with == "validation":
            raise WorkerValidationError("Malformed event payload")
        elif self.should_fail_with == "transient":
            raise WorkerTransientError("Database timeout")
        elif self.should_fail_with == "internal":
            raise ValueError("Unexpected NoneType")

def create_event(event_id: str, org_id: str = "org1") -> PersistentEvent:
    return PersistentEvent(
        event_id=event_id,
        org_id=org_id,
        event_type="CLOUD_EVENT",
        created_at=datetime.now(timezone.utc),
        source="CLOUD",
        correlation_id="",
        payload={"data": "test"}
    )

@pytest.mark.asyncio
async def test_validation_error_goes_to_dlq():
    store = InMemoryEventStore()
    await store.add_event(create_event("e1"))
    
    worker = MockRetryWorker("w1", "org1", store)
    worker.should_fail_with = "validation"
    
    await worker.start()
    await asyncio.sleep(0.2) # Allow worker to process
    
    ev = await store.get_event("org1", "e1")
    assert ev.status == EventState.DEAD_LETTER
    assert ev.attempt_count == 1
    assert "Malformed event payload" in ev.last_error
    
    await worker.stop()

@pytest.mark.asyncio
async def test_transient_error_retries_and_fencing_transfer():
    store = InMemoryEventStore()
    await store.add_event(create_event("e2"))
    
    # Claim it manually to simulate worker A
    ev_claim1 = await store.claim_next_event("workerA", ["CLOUD_EVENT"])
    assert ev_claim1 is not None
    token_A = ev_claim1.fencing_token
    
    # Worker A fails with transient error
    await store.update_event_state("org1", "e2", "workerA", token_A, EventState.FAILED, "Timeout", fatal=False)
    
    # Event should be RETRY_WAIT and claimable
    ev = await store.get_event("org1", "e2")
    assert ev.status == EventState.RETRY_WAIT
    assert ev.claimed_by is None
    
    # Worker B claims it
    ev_claim2 = await store.claim_next_event("workerB", ["CLOUD_EVENT"])
    assert ev_claim2 is not None
    assert ev_claim2.event_id == "e2"
    token_B = ev_claim2.fencing_token
    assert token_B != token_A
    assert ev_claim2.attempt_count == 2
    
    # Worker A zombie attempt fails
    assert await store.update_event_state("org1", "e2", "workerA", token_A, EventState.COMPLETED) is False
    
    # Worker B finishes
    assert await store.update_event_state("org1", "e2", "workerB", token_B, EventState.COMPLETED) is True
    
    ev_final = await store.get_event("org1", "e2")
    assert ev_final.status == EventState.COMPLETED

@pytest.mark.asyncio
async def test_bounded_internal_error_retries():
    store = InMemoryEventStore()
    await store.add_event(create_event("e3"))
    
    for i in range(1, 4):
        claim = await store.claim_next_event("w", ["CLOUD_EVENT"])
        assert claim is not None
        assert claim.attempt_count == i
        
        await store.update_event_state("org1", "e3", "w", claim.fencing_token, EventState.FAILED, "Internal Error", fatal=False)
        
        ev = await store.get_event("org1", "e3")
        if i < 3:
            assert ev.status == EventState.RETRY_WAIT
        else:
            assert ev.status == EventState.DEAD_LETTER
            
    # Should not be claimable anymore
    assert await store.claim_next_event("w", ["CLOUD_EVENT"]) is None

@pytest.mark.asyncio
async def test_secret_scrubbing_in_errors():
    store = InMemoryEventStore()
    await store.add_event(create_event("e4", org_id="SECRET_ORG_123"))
    
    worker = MockRetryWorker("w1", "SECRET_ORG_123", store)
    worker.should_fail_with = "internal" # Raises ValueError("Unexpected NoneType") but we can inject a secret
    
    # Overriding to raise a secret
    async def process_with_secret(event):
        raise Exception("Failed connecting to SECRET_ORG_123 database")
    worker.process_event = process_with_secret
    
    await worker.start()
    await asyncio.sleep(0.2)
    
    ev = await store.get_event("SECRET_ORG_123", "e4")
    assert ev.status == EventState.DEAD_LETTER
    assert ev.attempt_count == 3
    # It should have scrubbed the organization_id
    assert "SECRET_ORG_123" not in ev.last_error
    assert "ORG_ID" in ev.last_error
    
    await worker.stop()
