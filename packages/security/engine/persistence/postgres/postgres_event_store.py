import logging
import uuid
from typing import List, Optional, Dict
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select, update, exc
from sqlalchemy.orm import selectinload

from security.models.persistent_state import PersistentEvent, EventState, RequeueRecord
from security.engine.persistence.base import EventStore
from security.engine.persistence.postgres.models import PersistentEventModel, RequeueRecordModel, Base

logger = logging.getLogger(__name__)

class PostgresEventStore(EventStore):
    def __init__(self, database_url: str):
        if not database_url:
            raise ValueError("DATABASE_URL is required for PostgresEventStore")
        
        # Ensure driver is asyncpg
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        self.engine = create_async_engine(
            database_url,
            pool_size=20,
            max_overflow=10,
            pool_timeout=30,
            pool_recycle=1800,
            echo=False,
        )
        self.SessionLocal = async_sessionmaker(bind=self.engine, class_=AsyncSession, expire_on_commit=False)

    async def add_event(self, event: PersistentEvent):
        async with self.SessionLocal() as session:
            async with session.begin():
                db_event = PersistentEventModel(
                    event_id=event.event_id,
                    org_id=event.org_id,
                    correlation_id=event.correlation_id,
                    event_type=event.event_type,
                    payload=event.payload,
                    source=event.source,
                    provenance=event.provenance,
                    status=event.status.value,
                    created_at=event.created_at,
                    updated_at=event.updated_at,
                    claimed_by=event.claimed_by,
                    fencing_token=event.fencing_token,
                    lease_expires_at=event.lease_expires_at,
                    attempt_count=event.attempt_count,
                    last_error=event.last_error,
                    requeue_count=event.requeue_count,
                )
                session.add(db_event)
                # also add requeue history if any
                for r in event.requeue_history:
                    db_r = RequeueRecordModel(
                        recovery_id=r.recovery_id,
                        org_id=r.org_id,
                        event_id=r.event_id,
                        requested_by=r.requested_by,
                        reason=r.reason,
                        previous_state=r.previous_state,
                        new_state=r.new_state,
                        timestamp=r.timestamp,
                        requeue_count=r.requeue_count
                    )
                    session.add(db_r)

    def _to_pydantic(self, db_event: PersistentEventModel, requeues: List[RequeueRecordModel]) -> PersistentEvent:
        requeue_history = []
        for r in requeues:
            requeue_history.append(RequeueRecord(
                recovery_id=r.recovery_id,
                org_id=r.org_id,
                event_id=r.event_id,
                requested_by=r.requested_by,
                reason=r.reason,
                previous_state=r.previous_state,
                new_state=r.new_state,
                timestamp=r.timestamp,
                requeue_count=r.requeue_count
            ))
            
        return PersistentEvent(
            event_id=db_event.event_id,
            org_id=db_event.org_id,
            correlation_id=db_event.correlation_id,
            event_type=db_event.event_type,
            payload=db_event.payload,
            source=db_event.source,
            provenance=db_event.provenance,
            status=EventState(db_event.status),
            created_at=db_event.created_at,
            updated_at=db_event.updated_at,
            claimed_by=db_event.claimed_by,
            fencing_token=db_event.fencing_token,
            lease_expires_at=db_event.lease_expires_at,
            attempt_count=db_event.attempt_count,
            last_error=db_event.last_error,
            requeue_count=db_event.requeue_count,
            requeue_history=requeue_history
        )

    async def get_event(self, org_id: str, event_id: str) -> Optional[PersistentEvent]:
        async with self.SessionLocal() as session:
            stmt = select(PersistentEventModel).where(
                PersistentEventModel.org_id == org_id,
                PersistentEventModel.event_id == event_id
            )
            result = await session.execute(stmt)
            db_event = result.scalar_one_or_none()
            if not db_event:
                return None
                
            req_stmt = select(RequeueRecordModel).where(
                RequeueRecordModel.org_id == org_id,
                RequeueRecordModel.event_id == event_id
            ).order_by(RequeueRecordModel.timestamp.asc())
            req_res = await session.execute(req_stmt)
            requeues = list(req_res.scalars().all())
            
            return self._to_pydantic(db_event, requeues)

    async def claim_next_event(self, worker_id: str, event_types: List[str], lease_duration_sec: int = 30) -> Optional[PersistentEvent]:
        now = datetime.now(timezone.utc)
        
        async with self.SessionLocal() as session:
            async with session.begin():
                # Find an eligible event and lock it
                # Eligible:
                # status == PENDING
                # OR (status == CLAIMED and lease_expires_at < now)
                # OR (status == RETRY_WAIT and lease_expires_at < now)
                
                stmt = select(PersistentEventModel).where(
                    PersistentEventModel.event_type.in_(event_types),
                    (
                        (PersistentEventModel.status == EventState.PENDING.value) |
                        ((PersistentEventModel.status == EventState.CLAIMED.value) & (PersistentEventModel.lease_expires_at < now)) |
                        ((PersistentEventModel.status == EventState.RETRY_WAIT.value) & (PersistentEventModel.lease_expires_at < now))
                    )
                ).with_for_update(skip_locked=True).limit(1)
                
                result = await session.execute(stmt)
                db_event = result.scalar_one_or_none()
                
                if not db_event:
                    return None
                    
                # Update it
                fencing_token = str(uuid.uuid4())
                expires_at = now + timedelta(seconds=lease_duration_sec)
                
                db_event.status = EventState.CLAIMED.value
                db_event.claimed_by = worker_id
                db_event.fencing_token = fencing_token
                db_event.lease_expires_at = expires_at
                db_event.updated_at = now
                db_event.attempt_count += 1
                
                # Fetch requeues to return full event
                req_stmt = select(RequeueRecordModel).where(
                    RequeueRecordModel.org_id == db_event.org_id,
                    RequeueRecordModel.event_id == db_event.event_id
                ).order_by(RequeueRecordModel.timestamp.asc())
                req_res = await session.execute(req_stmt)
                requeues = list(req_res.scalars().all())
                
                return self._to_pydantic(db_event, requeues)

    async def renew_lease(self, org_id: str, event_id: str, worker_id: str, fencing_token: str, duration_sec: int = 30) -> bool:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=duration_sec)
        
        async with self.SessionLocal() as session:
            async with session.begin():
                stmt = select(PersistentEventModel).where(
                    PersistentEventModel.org_id == org_id,
                    PersistentEventModel.event_id == event_id,
                    PersistentEventModel.claimed_by == worker_id,
                    PersistentEventModel.fencing_token == fencing_token
                ).with_for_update()
                
                result = await session.execute(stmt)
                db_event = result.scalar_one_or_none()
                
                if not db_event:
                    return False
                    
                db_event.lease_expires_at = expires_at
                db_event.updated_at = now
                return True

    async def update_event_state(self, org_id: str, event_id: str, worker_id: str, fencing_token: str, state: EventState, error_msg: Optional[str] = None, fatal: bool = False) -> bool:
        now = datetime.now(timezone.utc)
        
        async with self.SessionLocal() as session:
            async with session.begin():
                stmt = select(PersistentEventModel).where(
                    PersistentEventModel.org_id == org_id,
                    PersistentEventModel.event_id == event_id,
                    PersistentEventModel.claimed_by == worker_id,
                    PersistentEventModel.fencing_token == fencing_token
                ).with_for_update()
                
                result = await session.execute(stmt)
                db_event = result.scalar_one_or_none()
                
                if not db_event:
                    return False
                    
                # State transition validation
                valid_transitions = {
                    EventState.PENDING: [EventState.CLAIMED],
                    EventState.CLAIMED: [EventState.PROCESSING, EventState.PENDING], # PENDING for rollback/reclaim
                    EventState.PROCESSING: [EventState.COMPLETED, EventState.FAILED, EventState.RETRY_WAIT, EventState.DEAD_LETTER],
                    EventState.RETRY_WAIT: [EventState.CLAIMED, EventState.DEAD_LETTER],
                }
                
                current_state = EventState(db_event.status)
                if state not in valid_transitions.get(current_state, []):
                    logger.warning(f"Invalid transition from {current_state} to {state}")
                    return False

                # Apply fatal or max_retry logic
                if state == EventState.FAILED:
                    if fatal or db_event.attempt_count >= 3:
                        state = EventState.DEAD_LETTER
                    else:
                        state = EventState.RETRY_WAIT
                
                db_event.status = state.value
                db_event.updated_at = now
                
                if error_msg:
                    db_event.last_error = error_msg
                    
                if state in [EventState.COMPLETED, EventState.DEAD_LETTER]:
                    db_event.fencing_token = None
                    db_event.claimed_by = None
                    db_event.lease_expires_at = None
                elif state == EventState.RETRY_WAIT:
                    db_event.fencing_token = None
                    db_event.claimed_by = None
                    # lease_expires_at acts as available_at in RETRY_WAIT
                    db_event.lease_expires_at = now + timedelta(seconds=10)
                return True

    async def requeue_dead_letter(self, org_id: str, event_id: str, requested_by: str, reason: str, max_requeues: int = 3) -> bool:
        now = datetime.now(timezone.utc)
        
        async with self.SessionLocal() as session:
            async with session.begin():
                stmt = select(PersistentEventModel).where(
                    PersistentEventModel.org_id == org_id,
                    PersistentEventModel.event_id == event_id
                ).with_for_update()
                
                result = await session.execute(stmt)
                db_event = result.scalar_one_or_none()
                
                if not db_event:
                    return False
                    
                if db_event.status != EventState.DEAD_LETTER.value:
                    return False
                    
                if db_event.requeue_count >= max_requeues:
                    return False
                    
                requeue_record = RequeueRecordModel(
                    recovery_id=str(uuid.uuid4()),
                    org_id=org_id,
                    event_id=event_id,
                    requested_by=requested_by,
                    reason=reason,
                    previous_state=db_event.status,
                    new_state=EventState.PENDING.value,
                    timestamp=now,
                    requeue_count=db_event.requeue_count + 1
                )
                
                db_event.status = EventState.PENDING.value
                db_event.requeue_count += 1
                db_event.attempt_count = 0
                db_event.last_error = None
                db_event.fencing_token = None
                db_event.claimed_by = None
                db_event.lease_expires_at = None
                db_event.updated_at = now
                
                session.add(requeue_record)
                return True
