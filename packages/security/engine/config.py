import os
import logging
from typing import Dict, Any, Optional

from security.engine.persistence.base import EventStore, AgentStateRepository, DetectionContextRepository, AttackStateRepository
from security.engine.persistence.memory import InMemoryEventStore
# Repositories for memory aren't strictly defined as separate classes in previous files,
# but we can provide mocks or leave them as None if not fully implemented in memory.

logger = logging.getLogger(__name__)

class PersistenceConfig:
    def __init__(self, environment: str, backend: str, database_url: Optional[str] = None):
        self.environment = environment
        self.backend = backend
        self.database_url = database_url

class PersistenceContainer:
    def __init__(self, event_store: EventStore,
                 agent_state_repo: Optional[AgentStateRepository] = None,
                 detection_context_repo: Optional[DetectionContextRepository] = None,
                 attack_state_repo: Optional[AttackStateRepository] = None,
                 engine=None):
        self.event_store = event_store
        self.agent_state_repo = agent_state_repo
        self.detection_context_repo = detection_context_repo
        self.attack_state_repo = attack_state_repo
        self._engine = engine
        
    async def shutdown(self):
        if self._engine:
            await self._engine.dispose()

def get_persistence_config() -> PersistenceConfig:
    env = os.getenv("ENVIRONMENT", "development")
    backend = os.getenv("PERSISTENCE_BACKEND", "memory")
    db_url = os.getenv("DATABASE_URL")
    return PersistenceConfig(environment=env, backend=backend, database_url=db_url)

def get_persistence_components(config: PersistenceConfig) -> PersistenceContainer:
    if config.environment == "production" and config.backend != "postgres":
        raise ValueError("Production environment must explicitly select 'postgres' backend. Fail-closed.")
        
    if config.backend == "postgres":
        if not config.database_url:
            raise ValueError("DATABASE_URL is missing/unavailable. Cannot start PostgreSQL persistence. Fail-closed.")
            
        try:
            # We must fail clearly if connectivity fails. We won't block synchronously since engine creation is async, 
            # but we can create the engine and session factories.
            from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
            from security.engine.persistence.postgres.postgres_event_store import PostgresEventStore
            from security.engine.persistence.postgres.postgres_repositories import (
                PostgresAgentStateRepository,
                PostgresDetectionContextRepository,
                PostgresAttackStateRepository
            )
            
            engine = create_async_engine(config.database_url, pool_size=10, max_overflow=20, pool_timeout=30, pool_recycle=1800)
            session_maker = async_sessionmaker(engine, expire_on_commit=False)
            
            event_store = PostgresEventStore(config.database_url, engine=engine)
            agent_repo = PostgresAgentStateRepository(session_maker)
            det_repo = PostgresDetectionContextRepository(session_maker)
            attack_repo = PostgresAttackStateRepository(session_maker)
            
            logger.info("persistence backend = postgres")
            
            return PersistenceContainer(
                event_store=event_store,
                agent_state_repo=agent_repo,
                detection_context_repo=det_repo,
                attack_state_repo=attack_repo,
                engine=engine
            )
        except Exception as e:
            logger.error(f"PostgreSQL initialization failed: {e}")
            raise ValueError(f"PostgreSQL connection failure fails clearly: {e}")
            
    elif config.backend == "memory":
        if config.environment == "production":
            raise ValueError("Production cannot use memory backend.")
            
        logger.info("persistence backend = memory")
        return PersistenceContainer(
            event_store=InMemoryEventStore(),
            agent_state_repo=None,
            detection_context_repo=None,
            attack_state_repo=None
        )
    else:
        raise ValueError(f"Unknown PERSISTENCE_BACKEND: {config.backend}")
