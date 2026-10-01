import os
import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

# Primary production DB config
DATABASE_URL = os.getenv("DATABASE_URL")
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")

engine = None
async_session_maker = None

def init_postgres():
    global engine, async_session_maker
    env = os.getenv("ENVIRONMENT", "development")
    
    url = TEST_DATABASE_URL if env == "test" and TEST_DATABASE_URL else DATABASE_URL
    
    if not url:
        logger.warning("No Postgres DATABASE_URL configured. Persistence will fail closed if Postgres is required.")
        return
        
    try:
        engine = create_async_engine(
            url,
            echo=False,
            future=True,
            pool_size=5,
            max_overflow=10
        )
        async_session_maker = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        logger.info(f"Initialized PostgreSQL engine for {env} environment.")
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL engine: {e}")

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    if not async_session_maker:
        raise RuntimeError("Database engine is not initialized. Ensure DATABASE_URL is set.")
    
    async with async_session_maker() as session:
        yield session

# Initialize synchronously if available
init_postgres()
