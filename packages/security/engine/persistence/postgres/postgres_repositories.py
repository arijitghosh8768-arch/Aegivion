import json
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy import select, delete

from security.engine.persistence.base import AgentStateRepository, DetectionContextRepository, AttackStateRepository
from security.engine.persistence.postgres.models import (
    PersistentAgentStateModel,
    PersistentWorkerStateModel,
    PersistentDetectionContextModel,
    PersistentAttackStateModel
)

class PostgresAgentStateRepository(AgentStateRepository):
    def __init__(self, session_maker: async_sessionmaker[AsyncSession]):
        self.SessionLocal = session_maker

    async def get_state(self, organization_id: str) -> Optional[dict]:
        async with self.SessionLocal() as session:
            stmt = select(PersistentAgentStateModel).where(PersistentAgentStateModel.organization_id == organization_id)
            result = await session.execute(stmt)
            obj = result.scalar_one_or_none()
            if obj:
                return {"organization_id": obj.organization_id, "state": obj.state}
            return None

    async def save_state(self, organization_id: str, state_data: dict):
        async with self.SessionLocal() as session:
            async with session.begin():
                stmt = select(PersistentAgentStateModel).where(PersistentAgentStateModel.organization_id == organization_id)
                result = await session.execute(stmt)
                obj = result.scalar_one_or_none()
                if not obj:
                    obj = PersistentAgentStateModel(organization_id=organization_id, state=state_data.get("state", "UNKNOWN"))
                    session.add(obj)
                else:
                    obj.state = state_data.get("state", "UNKNOWN")

class PostgresDetectionContextRepository(DetectionContextRepository):
    def __init__(self, session_maker: async_sessionmaker[AsyncSession]):
        self.SessionLocal = session_maker

    async def get_context(self, org_id: str) -> Optional[dict]:
        async with self.SessionLocal() as session:
            stmt = select(PersistentDetectionContextModel).where(PersistentDetectionContextModel.org_id == org_id)
            result = await session.execute(stmt)
            obj = result.scalar_one_or_none()
            if obj:
                return {"events": obj.events, "detections": obj.detections}
            return None

    async def save_context(self, org_id: str, context_data: dict):
        async with self.SessionLocal() as session:
            async with session.begin():
                stmt = select(PersistentDetectionContextModel).where(PersistentDetectionContextModel.org_id == org_id)
                result = await session.execute(stmt)
                obj = result.scalar_one_or_none()
                if not obj:
                    obj = PersistentDetectionContextModel(org_id=org_id, events=context_data.get("events", []), detections=context_data.get("detections", []))
                    session.add(obj)
                else:
                    obj.events = context_data.get("events", [])
                    obj.detections = context_data.get("detections", [])

class PostgresAttackStateRepository(AttackStateRepository):
    def __init__(self, session_maker: async_sessionmaker[AsyncSession]):
        self.SessionLocal = session_maker

    async def get_state(self, org_id: str) -> Optional[dict]:
        async with self.SessionLocal() as session:
            stmt = select(PersistentAttackStateModel).where(PersistentAttackStateModel.org_id == org_id)
            result = await session.execute(stmt)
            obj = result.scalar_one_or_none()
            if obj:
                return obj.state_data
            return None

    async def save_state(self, org_id: str, state_data: dict):
        async with self.SessionLocal() as session:
            async with session.begin():
                stmt = select(PersistentAttackStateModel).where(PersistentAttackStateModel.org_id == org_id)
                result = await session.execute(stmt)
                obj = result.scalar_one_or_none()
                if not obj:
                    obj = PersistentAttackStateModel(org_id=org_id, state_data=state_data)
                    session.add(obj)
                else:
                    obj.state_data = state_data
