import os
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from app.database.postgres_foundation import init_postgres, get_db_session

pytestmark = pytest.mark.asyncio

async def is_postgres_available():
    url = os.getenv("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not url or "postgres" not in url:
        return False
    try:
        engine = create_async_engine(url, connect_args={"timeout": 1})
        async with engine.begin() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

@pytest_asyncio.fixture(scope="module")
async def check_pg():
    available = await is_postgres_available()
    if not available:
        if os.getenv("PHASE6_VERIFICATION") == "1":
            pytest.fail("PHASE6_VERIFICATION is active, but PostgreSQL is unavailable. Failing strictly.")
        else:
            pytest.skip("PostgreSQL is unavailable. Skipping integration tests.")
    return available

async def test_twin_persistence_repository(check_pg):
    # Future placeholder to verify TwinPersistenceRepository saves/loads correctly
    pass

async def test_agent_state_repository(check_pg):
    # Future placeholder for AgentStateRepository
    pass
