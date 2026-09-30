import pytest
from datetime import datetime, timezone
import asyncio
from typing import Dict, Any

from security.models.distributed_health import WorkerIdentity, HealthState
from security.engine.persistence.health_repository import InMemoryWorkerHealthRepository
from security.engine.distributed_health_monitor import DistributedHealthMonitor
from security.utils.clock import Clock, FrozenClock

@pytest.fixture
def clock():
    dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    c = FrozenClock(dt)
    Clock.set_instance(c)
    yield c
    Clock.set_instance(None)

@pytest.fixture
def repo():
    return InMemoryWorkerHealthRepository()

@pytest.fixture
def monitor(repo):
    return DistributedHealthMonitor(repository=repo)

@pytest.mark.asyncio
async def test_worker_registration_and_idempotency(clock, repo):
    w = WorkerIdentity(
        node_id="n1",
        worker_id="w1",
        worker_type="EVENT_INGESTION",
        started_at=clock.now(),
        last_heartbeat=clock.now(),
        updated_at=clock.now(),
        queue_capacity=100
    )
    
    assert await repo.register_worker(w)
    assert len(await repo.list_workers()) == 1
    
    # idempotent
    w2 = WorkerIdentity(
        node_id="n1",
        worker_id="w1",
        worker_type="EVENT_INGESTION",
        started_at=clock.now(),
        last_heartbeat=clock.now(),
        updated_at=clock.now(),
        queue_capacity=200
    )
    assert await repo.register_worker(w2)
    assert len(await repo.list_workers()) == 1
    stored = await repo.get_worker("w1")
    assert stored.queue_capacity == 200

@pytest.mark.asyncio
async def test_heartbeat_persistence(clock, repo):
    w = WorkerIdentity(
        node_id="n1",
        worker_id="w1",
        worker_type="EVENT_INGESTION",
        started_at=clock.now(),
        last_heartbeat=clock.now(),
        updated_at=clock.now()
    )
    await repo.register_worker(w)
    
    clock.advance(5)
    await repo.heartbeat("w1", {"queue_depth": 5, "events_processed": 10})
    
    stored = await repo.get_worker("w1")
    assert stored.queue_depth == 5
    assert stored.events_processed == 10
    assert stored.last_heartbeat == clock.now()

@pytest.mark.asyncio
async def test_stale_detection(clock, repo, monitor):
    w = WorkerIdentity(
        node_id="n1",
        worker_id="w1",
        worker_type="EVENT_INGESTION",
        started_at=clock.now(),
        last_heartbeat=clock.now(),
        updated_at=clock.now()
    )
    await repo.register_worker(w)
    
    clock.advance(16)
    await monitor.check_stale_workers()
    
    stored = await repo.get_worker("w1")
    assert stored.state == HealthState.STALE

@pytest.mark.asyncio
async def test_cluster_health_calculation(clock, repo, monitor):
    # Setup workers
    w1 = WorkerIdentity(node_id="n1", worker_id="w1", worker_type="EVENT_INGESTION", 
                       started_at=clock.now(), last_heartbeat=clock.now(), updated_at=clock.now(),
                       queue_capacity=100)
    w2 = WorkerIdentity(node_id="n1", worker_id="w2", worker_type="EVENT_INGESTION", 
                       started_at=clock.now(), last_heartbeat=clock.now(), updated_at=clock.now(),
                       queue_capacity=100)
    w3 = WorkerIdentity(node_id="n2", worker_id="w3", worker_type="DETECTION_CORRELATION", 
                       started_at=clock.now(), last_heartbeat=clock.now(), updated_at=clock.now(),
                       queue_capacity=100)
                       
    await repo.register_worker(w1)
    await repo.register_worker(w2)
    await repo.register_worker(w3)
    
    snap = await monitor.get_health_snapshot()
    assert snap.overall_state == HealthState.HEALTHY
    assert snap.total_workers == 3
    assert len(snap.nodes) == 2
    
    # 1 ingestion worker fails, we have 2, so cluster degrades but doesn't fail
    await repo.mark_failed("w1")
    snap = await monitor.get_health_snapshot()
    assert snap.overall_state == HealthState.DEGRADED
    
    # all ingestion fail -> FAILED
    await repo.mark_failed("w2")
    snap = await monitor.get_health_snapshot()
    assert snap.overall_state == HealthState.FAILED
    assert "No healthy ingestion capacity" in snap.health_reason
    
    # Node 1 is FAILED because both its workers failed
    n1_health = next(n for n in snap.nodes if n.node_id == "n1")
    assert n1_health.state == HealthState.FAILED

@pytest.mark.asyncio
async def test_queue_pressure_degrades(clock, repo, monitor):
    w1 = WorkerIdentity(node_id="n1", worker_id="w1", worker_type="EVENT_INGESTION", 
                       started_at=clock.now(), last_heartbeat=clock.now(), updated_at=clock.now(),
                       queue_capacity=100, queue_depth=95)
                       
    await repo.register_worker(w1)
    
    snap = await monitor.get_health_snapshot()
    # utilization > 90%
    assert snap.overall_state == HealthState.DEGRADED
    assert "pressure" in snap.health_reason
    
@pytest.mark.asyncio
async def test_worker_recovery_path(clock, repo, monitor):
    w1 = WorkerIdentity(node_id="n1", worker_id="w1", worker_type="EVENT_INGESTION", 
                       started_at=clock.now(), last_heartbeat=clock.now(), updated_at=clock.now(),
                       queue_capacity=100)
    await repo.register_worker(w1)
    
    clock.advance(20)
    await monitor.check_stale_workers()
    stored = await repo.get_worker("w1")
    assert stored.state == HealthState.STALE
    
    # Simulate restart/recovery (new heartbeat with state healthy)
    await repo.heartbeat("w1", {"state": HealthState.HEALTHY})
    stored = await repo.get_worker("w1")
    assert stored.state == HealthState.HEALTHY
    
    # Snapshot should be healthy again
    snap = await monitor.get_health_snapshot()
    assert snap.overall_state == HealthState.HEALTHY
