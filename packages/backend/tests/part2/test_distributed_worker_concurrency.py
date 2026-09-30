import asyncio
import pytest
from datetime import datetime, timezone, timedelta
import uuid

from security.models.persistent_state import PersistentEvent, EventState
from security.engine.persistence.memory import InMemoryEventStore

@pytest.fixture
def store():
    return InMemoryEventStore()

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
async def test_single_event_contention(store):
    await store.add_event(create_event("e1"))
    
    # Two workers try to claim simultaneously
    claim1_task = store.claim_next_event("workerA", ["CLOUD_EVENT"])
    claim2_task = store.claim_next_event("workerB", ["CLOUD_EVENT"])
    
    res1, res2 = await asyncio.gather(claim1_task, claim2_task)
    
    # One succeeds, one fails
    assert (res1 is not None and res2 is None) or (res1 is None and res2 is not None)
    
    claimed = res1 if res1 else res2
    assert claimed.event_id == "e1"
    assert claimed.fencing_token is not None

@pytest.mark.asyncio
async def test_many_events_many_workers(store):
    for i in range(100):
        await store.add_event(create_event(f"e{i}"))
        
    async def worker_loop(worker_id: str):
        claimed_events = []
        while True:
            ev = await store.claim_next_event(worker_id, ["CLOUD_EVENT"])
            if not ev:
                break
            claimed_events.append(ev)
            await asyncio.sleep(0.001)
        return claimed_events

    workers = [worker_loop(f"w{i}") for i in range(4)]
    results = await asyncio.gather(*workers)
    
    all_claimed = []
    for r in results:
        all_claimed.extend(r)
        
    assert len(all_claimed) == 100
    event_ids = set(e.event_id for e in all_claimed)
    assert len(event_ids) == 100 # No duplicates

@pytest.mark.asyncio
async def test_lease_expiration_and_fencing(store):
    await store.add_event(create_event("e1"))
    
    # Worker A claims, gets short lease
    workerA_claim = await store.claim_next_event("workerA", ["CLOUD_EVENT"], lease_duration_sec=1)
    assert workerA_claim is not None
    token_A = workerA_claim.fencing_token
    
    # Worker B tries to claim immediately - should fail
    workerB_claim = await store.claim_next_event("workerB", ["CLOUD_EVENT"])
    assert workerB_claim is None
    
    # Mock time advance by actually sleeping to let lease expire
    await asyncio.sleep(1.1)
    
    # Worker B claims after lease expires
    workerB_claim2 = await store.claim_next_event("workerB", ["CLOUD_EVENT"])
    assert workerB_claim2 is not None
    token_B = workerB_claim2.fencing_token
    
    assert workerB_claim2.claimed_by == "workerB"
    assert token_A != token_B
    
    # Zombie Worker A tries to renew lease - REJECTED
    renew_A = await store.renew_lease("org1", "e1", "workerA", token_A)
    assert renew_A is False
    
    # Zombie Worker A tries to update state - REJECTED
    update_A = await store.update_event_state("org1", "e1", "workerA", token_A, EventState.COMPLETED)
    assert update_A is False
    
    # Worker B updates state - SUCCESS
    update_B = await store.update_event_state("org1", "e1", "workerB", token_B, EventState.COMPLETED)
    assert update_B is True
    
    final = await store.get_event("org1", "e1")
    assert final.status == EventState.COMPLETED

@pytest.mark.asyncio
async def test_concurrent_different_events(store):
    await store.add_event(create_event("e1"))
    await store.add_event(create_event("e2"))
    await store.add_event(create_event("e3"))
    
    # Claim sequentially to guarantee one each (or concurrently, but we just want to ensure all get one)
    c1 = await store.claim_next_event("wA", ["CLOUD_EVENT"])
    c2 = await store.claim_next_event("wB", ["CLOUD_EVENT"])
    c3 = await store.claim_next_event("wC", ["CLOUD_EVENT"])
    
    assert c1.event_id == "e1"
    assert c2.event_id == "e2"
    assert c3.event_id == "e3"

@pytest.mark.asyncio
async def test_tenant_isolation(store):
    # Two identical event IDs, but different tenants
    await store.add_event(create_event("e1", org_id="orgA"))
    await store.add_event(create_event("e1", org_id="orgB"))
    
    # Claiming should pull both sequentially
    claim_1 = await store.claim_next_event("w1", ["CLOUD_EVENT"])
    claim_2 = await store.claim_next_event("w2", ["CLOUD_EVENT"])
    
    assert claim_1 is not None
    assert claim_2 is not None
    
    assert claim_1.event_id == "e1"
    assert claim_2.event_id == "e1"
    
    assert {claim_1.org_id, claim_2.org_id} == {"orgA", "orgB"}
    
    # Updating one does not affect the other
    await store.update_event_state(claim_1.org_id, claim_1.event_id, "w1", claim_1.fencing_token, EventState.COMPLETED)
    
    orgA_ev = await store.get_event("orgA", "e1")
    orgB_ev = await store.get_event("orgB", "e1")
    
    if claim_1.org_id == "orgA":
        assert orgA_ev.status == EventState.COMPLETED
        assert orgB_ev.status == EventState.CLAIMED
    else:
        assert orgB_ev.status == EventState.COMPLETED
        assert orgA_ev.status == EventState.CLAIMED
