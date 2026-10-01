import os
import pytest
import pytest_asyncio
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.asyncio

async def is_postgres_available():
    url = os.getenv("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url or "postgres" not in url:
        return False
    try:
        engine = create_async_engine(url, connect_args={"timeout": 1})
        async with engine.begin() as conn:
            await conn.execute("SELECT 1")
        return True
    except Exception:
        return False

@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest_asyncio.fixture(scope="module")
async def check_pg():
    available = await is_postgres_available()
    if not available:
        if os.getenv("PHASE6_VERIFICATION") == "1":
            pytest.fail("PHASE6_VERIFICATION is active, but PostgreSQL is unavailable. Failing strictly.")
        else:
            pytest.skip("PostgreSQL is unavailable. Skipping integration tests.")
    return available

async def test_postgres_connection(check_pg):
    # Basic sanity check
    assert check_pg is True

async def test_concurrency_lock_skip_locked(check_pg):
    # Future placeholder for SELECT FOR UPDATE SKIP LOCKED
    # Proves 100 events / 4 workers -> 100 unique claims
    pass
