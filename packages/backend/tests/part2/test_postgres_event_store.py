import pytest
import os
import uuid
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import create_async_engine

from security.models.persistent_state import PersistentEvent, EventState
from security.engine.persistence.postgres.postgres_event_store import PostgresEventStore
from security.engine.persistence.postgres.models import Base

# Determine if Postgres is available. The asyncpg driver is required here, so
# the synchronous ``TEST_DATABASE_URL`` (psycopg2) is adapted rather than used
# as-is. The database name must end in ``_test``: this module creates/drops
# schema, so pointing it at the application database would be destructive.
def _async_test_url() -> str | None:
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        return None
    url = url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if "+asyncpg://" not in url:
        return None
    database = url.rsplit("/", 1)[-1].split("?", 1)[0]
    if not database.endswith("_test"):
        return None
    return url


TEST_DATABASE_URL = _async_test_url()


def init_db() -> bool:
    """Ensure the event-store tables exist. Never drops existing tables."""
    if not TEST_DATABASE_URL:
        return False
    try:
        engine = create_async_engine(TEST_DATABASE_URL)

        async def create():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            await engine.dispose()

        asyncio.run(create())
        return True
    except Exception:
        return False


GLOBAL_ENGINE = init_db()


@pytest.fixture
def store():
    if not GLOBAL_ENGINE:
        pytest.skip("Isolated async PostgreSQL test database is unavailable")
    s = PostgresEventStore(TEST_DATABASE_URL)

    async def clean_and_dispose():
        async with s.engine.begin() as conn:
            for table in reversed(Base.metadata.sorted_tables):
                await conn.execute(table.delete())
        # asyncpg connections belong to the loop that opened them. Disposing the
        # pool here means the test body (its own asyncio.run loop) opens fresh
        # connections instead of reusing ones bound to this now-closed loop.
        await s.engine.dispose()

    asyncio.run(clean_and_dispose())
    try:
        yield s
    finally:
        # Leave no rows behind. Cleanup uses a plain synchronous connection: the
        # test body's engine pool belongs to the asyncio loop that has just been
        # closed, so reusing it from a new loop would leak rows.
        try:
            from sqlalchemy import create_engine

            sync_url = TEST_DATABASE_URL.replace(
                "postgresql+asyncpg://", "postgresql+psycopg2://", 1
            )
            sync_engine = create_engine(sync_url)
            try:
                with sync_engine.begin() as conn:
                    for table in reversed(Base.metadata.sorted_tables):
                        conn.execute(table.delete())
            finally:
                sync_engine.dispose()
        except Exception:  # best-effort cleanup of an isolated test database
            pass

def _make_event(org_id="org1", event_id=None, event_type="TEST_TYPE", status=EventState.PENDING):
    return PersistentEvent(
        org_id=org_id,
        event_id=event_id or str(uuid.uuid4()),
        event_type=event_type,
        status=status,
        payload={"key": "val"}
    )

def test_insert_and_retrieve_event(store: PostgresEventStore):
    async def run():
        event = _make_event(event_id="E001")
        await store.add_event(event)
        
        retrieved = await store.get_event("org1", "E001")
        assert retrieved is not None
        assert retrieved.event_id == "E001"
        assert retrieved.org_id == "org1"
        assert retrieved.status == EventState.PENDING
    asyncio.run(run())

def test_tenant_isolation(store: PostgresEventStore):
    async def run():
        event1 = _make_event(org_id="orgA", event_id="E001")
        event2 = _make_event(org_id="orgB", event_id="E001")
        
        await store.add_event(event1)
        await store.add_event(event2)
        
        ret1 = await store.get_event("orgA", "E001")
        ret2 = await store.get_event("orgB", "E001")
        
        assert ret1 is not None and ret1.org_id == "orgA"
        assert ret2 is not None and ret2.org_id == "orgB"
        assert ret1.event_id == ret2.event_id
    asyncio.run(run())

def test_atomic_claim(store: PostgresEventStore):
    async def run():
        event = _make_event(event_type="TYPE_A")
        await store.add_event(event)
        
        claimed = await store.claim_next_event("worker1", ["TYPE_A"])
        assert claimed is not None
        assert claimed.status == EventState.CLAIMED
        assert claimed.claimed_by == "worker1"
        assert claimed.fencing_token is not None
        
        # Second claim should get nothing
        claimed2 = await store.claim_next_event("worker2", ["TYPE_A"])
        assert claimed2 is None
    asyncio.run(run())

def test_concurrent_claim(store: PostgresEventStore):
    async def run():
        event = _make_event(event_type="TYPE_CONC")
        await store.add_event(event)
        
        # 4 concurrent claims
        results = await asyncio.gather(
            store.claim_next_event("w1", ["TYPE_CONC"]),
            store.claim_next_event("w2", ["TYPE_CONC"]),
            store.claim_next_event("w3", ["TYPE_CONC"]),
            store.claim_next_event("w4", ["TYPE_CONC"])
        )
        
        successful_claims = [r for r in results if r is not None]
        assert len(successful_claims) == 1
    asyncio.run(run())

def test_lease_renewal_and_stale_rejection(store: PostgresEventStore):
    async def run():
        event = _make_event(event_type="TYPE_L")
        await store.add_event(event)
        
        claimed = await store.claim_next_event("w1", ["TYPE_L"])
        
        # Renew valid
        success = await store.renew_lease(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, 30)
        assert success is True
        
        # Renew wrong token
        success_stale = await store.renew_lease(claimed.org_id, claimed.event_id, "w1", "wrong_token", 30)
        assert success_stale is False
    asyncio.run(run())

def test_state_transition_validation(store: PostgresEventStore):
    async def run():
        event = _make_event(event_type="TYPE_S")
        await store.add_event(event)
        claimed = await store.claim_next_event("w1", ["TYPE_S"])
        
        # valid: CLAIMED -> PROCESSING
        res = await store.update_event_state(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, EventState.PROCESSING)
        assert res is True
        
        # invalid: PROCESSING -> PENDING
        res_inv = await store.update_event_state(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, EventState.PENDING)
        assert res_inv is False
        
        ret = await store.get_event(claimed.org_id, claimed.event_id)
        assert ret.status == EventState.PROCESSING
    asyncio.run(run())

def test_fatal_error_dead_letter(store: PostgresEventStore):
    async def run():
        event = _make_event(event_type="TYPE_F")
        await store.add_event(event)
        claimed = await store.claim_next_event("w1", ["TYPE_F"])
        
        await store.update_event_state(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, EventState.PROCESSING)
        await store.update_event_state(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, EventState.FAILED, fatal=True)
        
        ret = await store.get_event(claimed.org_id, claimed.event_id)
        assert ret.status == EventState.DEAD_LETTER
        assert ret.claimed_by is None
        assert ret.fencing_token is None
    asyncio.run(run())

def test_max_retries_dead_letter(store: PostgresEventStore):
    async def run():
        event = _make_event(event_type="TYPE_R")
        await store.add_event(event)
        
        for _ in range(3): # Attempt 1, 2, 3
            claimed = await store.claim_next_event("w1", ["TYPE_R"])
            await store.update_event_state(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, EventState.PROCESSING)
            await store.update_event_state(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, EventState.FAILED, fatal=False)
            
            # After updating to failed (not fatal), if it hit max retries it should be DEAD_LETTER
            ret = await store.get_event(claimed.org_id, claimed.event_id)
            if ret.status == EventState.DEAD_LETTER:
                break
                
            # Simulate wait time so it can be reclaimed
            async with store.SessionLocal() as session:
                from sqlalchemy import text
                await session.execute(text("UPDATE persistent_events SET lease_expires_at = '2000-01-01T00:00:00Z'"))
                await session.commit()
                
        ret = await store.get_event(event.org_id, event.event_id)
        assert ret.status == EventState.DEAD_LETTER
        assert ret.attempt_count == 3
    asyncio.run(run())

def test_lease_expiration_and_reclaim(store: PostgresEventStore):
    async def run():
        event = _make_event(event_type="TYPE_EXP")
        await store.add_event(event)
        
        # claim with short lease
        claimed = await store.claim_next_event("w1", ["TYPE_EXP"], lease_duration_sec=-1) # expires in past
        assert claimed is not None
        
        # second worker can reclaim because lease expired
        claimed2 = await store.claim_next_event("w2", ["TYPE_EXP"])
        assert claimed2 is not None
        assert claimed2.claimed_by == "w2"
        assert claimed2.fencing_token != claimed.fencing_token
        
        # Worker 1 tries to update, should fail
        res = await store.update_event_state(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, EventState.PROCESSING)
        assert res is False
    asyncio.run(run())

def test_explicit_dlq_requeue(store: PostgresEventStore):
    async def run():
        event = _make_event(event_type="TYPE_DLQ")
        await store.add_event(event)
        claimed = await store.claim_next_event("w1", ["TYPE_DLQ"])
        await store.update_event_state(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, EventState.PROCESSING)
        await store.update_event_state(claimed.org_id, claimed.event_id, "w1", claimed.fencing_token, EventState.FAILED, fatal=True)
        
        ret = await store.get_event(claimed.org_id, claimed.event_id)
        assert ret.status == EventState.DEAD_LETTER
        
        res = await store.requeue_dead_letter(claimed.org_id, claimed.event_id, "admin", "fix deployed")
        assert res is True
        
        ret2 = await store.get_event(claimed.org_id, claimed.event_id)
        assert ret2.status == EventState.PENDING
        assert ret2.requeue_count == 1
        assert len(ret2.requeue_history) == 1
        assert ret2.requeue_history[0].reason == "fix deployed"
    asyncio.run(run())
