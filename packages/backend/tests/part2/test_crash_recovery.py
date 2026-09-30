import asyncio
import pytest
from datetime import datetime, timezone, timedelta

from security.models.persistent_state import PersistentEvent, EventState
from security.models.distributed_health import HealthState
from security.engine.persistence.memory import InMemoryEventStore
from security.engine.persistence.health_repository import InMemoryWorkerHealthRepository
from security.engine.distributed_health_monitor import DistributedHealthMonitor
from security.engine.agent_recovery import AgentRecoveryManager
from security.engine.crash_recovery import CrashRecoveryManager
from security.engine.agent_workers import AsyncQueueWorker
from security.engine.agent_controller import WorkerType, WorkerState
from security.utils.clock import FrozenClock, Clock

@pytest.fixture
def clock():
    c = FrozenClock(datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc))
    Clock.set_instance(c)
    yield c
    Clock.set_instance(None)

@pytest.fixture
def store():
    return InMemoryEventStore()

@pytest.fixture
def health_repo():
    return InMemoryWorkerHealthRepository()

@pytest.fixture
def monitor(health_repo):
    return DistributedHealthMonitor(health_repo, stale_timeout_seconds=15)

@pytest.fixture
def recovery_mgr():
    return AgentRecoveryManager(max_restart_attempts=3, restart_backoff_seconds=0, maximum_backoff_seconds=0)

@pytest.fixture
def crash_mgr(store, monitor, recovery_mgr):
    return CrashRecoveryManager(store, monitor, recovery_mgr)

def create_event(event_id: str, org_id: str = "org1") -> PersistentEvent:
    return PersistentEvent(
        event_id=event_id,
        org_id=org_id,
        event_type="CLOUD_EVENT",
        source="CLOUD"
    )

class MockCrashWorker(AsyncQueueWorker):
    async def process_event(self, event):
        pass

@pytest.mark.asyncio
async def test_zombie_mutations_rejected(store, clock):
    await store.add_event(create_event("e1"))
    
    # Worker A claims with 5 sec lease
    ev1 = await store.claim_next_event("workerA", ["CLOUD_EVENT"], lease_duration_sec=5)
    assert ev1 is not None
    token_a = ev1.fencing_token
    
    # Fast forward to lease expiration
    clock.advance(6)
    
    # Worker B reclaims
    ev2 = await store.claim_next_event("workerB", ["CLOUD_EVENT"])
    assert ev2 is not None
    assert ev2.event_id == "e1"
    token_b = ev2.fencing_token
    assert token_a != token_b
    
    # Worker A attempts zombie actions - ALL REJECTED
    assert await store.renew_lease("org1", "e1", "workerA", token_a) is False
    assert await store.update_event_state("org1", "e1", "workerA", token_a, EventState.COMPLETED) is False
    assert await store.update_event_state("org1", "e1", "workerA", token_a, EventState.FAILED, "error") is False
    
    # Worker B completes
    assert await store.update_event_state("org1", "e1", "workerB", token_b, EventState.COMPLETED) is True

@pytest.mark.asyncio
async def test_dead_letter_controlled_requeue(store, crash_mgr):
    await store.add_event(create_event("e1"))
    ev1 = await store.claim_next_event("workerA", ["CLOUD_EVENT"])
    
    # Fail fatally
    await store.update_event_state("org1", "e1", "workerA", ev1.fencing_token, EventState.FAILED, "fatal", fatal=True)
    
    ev_dl = await store.get_event("org1", "e1")
    assert ev_dl.status == EventState.DEAD_LETTER
    
    # Automatically reclaiming must NOT resurrect it
    assert await store.claim_next_event("workerB", ["CLOUD_EVENT"]) is None
    
    # Requeue explicit
    success = await crash_mgr.requeue_dead_letter("org1", "e1", "admin", "fix deployed")
    assert success is True
    
    ev_req = await store.get_event("org1", "e1")
    assert ev_req.status == EventState.PENDING
    assert ev_req.requeue_count == 1
    assert len(ev_req.requeue_history) == 1
    assert ev_req.requeue_history[0].reason == "fix deployed"
    assert ev_req.requeue_history[0].requested_by == "admin"
    
    # Claim again
    ev_claim2 = await store.claim_next_event("workerB", ["CLOUD_EVENT"])
    assert ev_claim2 is not None
    assert ev_claim2.event_id == "e1"

@pytest.mark.asyncio
async def test_poison_event_protection_max_requeues(store, crash_mgr):
    await store.add_event(create_event("e1"))
    
    for i in range(3):
        # Claim
        ev_claim = await store.claim_next_event("w", ["CLOUD_EVENT"])
        assert ev_claim is not None
        # Fail
        await store.update_event_state("org1", "e1", "w", ev_claim.fencing_token, EventState.FAILED, "error", fatal=True)
        # Requeue
        assert await crash_mgr.requeue_dead_letter("org1", "e1", "admin", "retry", max_requeues=2) == (i < 2)

    ev_final = await store.get_event("org1", "e1")
    assert ev_final.status == EventState.DEAD_LETTER
    assert ev_final.requeue_count == 2
    assert crash_mgr.metrics["dead_letter_requeue_denied"] == 1

@pytest.mark.asyncio
async def test_worker_crash_and_recovery(health_repo, monitor, recovery_mgr, crash_mgr, clock):
    w1 = MockCrashWorker("w1", WorkerType.EVENT_INGESTION, "org1", node_id="nodeA", health_repository=health_repo)
    await w1.start()
    
    # Wait for heartbeat
    clock.advance(1)
    await w1.heartbeat_async()
    
    snap1 = await monitor.get_health_snapshot()
    w1_health = await health_repo.get_worker("w1")
    assert w1_health.state == HealthState.HEALTHY
    
    # Simulate crash (stop heartbeating, advance time)
    clock.advance(20) # exceeds 15s timeout
    # Run check_stale_workers to mark it stale
    await monitor.check_stale_workers()
    
    snap2 = await monitor.get_health_snapshot()
    w1_health = await health_repo.get_worker("w1")
    assert w1_health.state == HealthState.STALE
    
    # Recover stale workers
    await crash_mgr.recover_stale_workers({"w1": w1})
    
    assert crash_mgr.metrics["worker_crashes"] == 1
    assert crash_mgr.metrics["recovery_success"] == 1
    
    # Allow restart to heartbeat
    await asyncio.sleep(0.1)
    await w1.heartbeat_async()
    
    snap3 = await monitor.get_health_snapshot()
    w1_health = await health_repo.get_worker("w1")
    assert w1_health.state == HealthState.HEALTHY
    
    await w1.stop()

@pytest.mark.asyncio
async def test_tenant_isolation_in_requeue(store, crash_mgr):
    await store.add_event(create_event("e1", "orgA"))
    await store.add_event(create_event("e1", "orgB"))
    
    claimA = await store.claim_next_event("w", ["CLOUD_EVENT"])
    claimB = await store.claim_next_event("w", ["CLOUD_EVENT"])
    
    await store.update_event_state(claimA.org_id, claimA.event_id, "w", claimA.fencing_token, EventState.FAILED, fatal=True)
    await store.update_event_state(claimB.org_id, claimB.event_id, "w", claimB.fencing_token, EventState.FAILED, fatal=True)
    
    assert await crash_mgr.requeue_dead_letter("orgA", "e1", "adm", "fix") is True
    
    evA = await store.get_event("orgA", "e1")
    evB = await store.get_event("orgB", "e1")
    
    assert evA.status == EventState.PENDING
    assert evB.status == EventState.DEAD_LETTER

@pytest.mark.asyncio
async def test_active_lease_not_force_expired(store, clock):
    await store.add_event(create_event("e1"))
    ev = await store.claim_next_event("w", ["CLOUD_EVENT"], lease_duration_sec=30)
    
    # Time advances 10 seconds.
    clock.advance(10)
    
    # Another worker attempts claim - rejected
    assert await store.claim_next_event("w2", ["CLOUD_EVENT"]) is None
    
    # Ensure event remains CLAIMED
    assert (await store.get_event("org1", "e1")).status == EventState.CLAIMED
