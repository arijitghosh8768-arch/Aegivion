import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict
import uuid
from security.models.persistent_state import PersistentEvent, EventState
from security.engine.persistence.base import EventStore, AgentStateRepository, DetectionContextRepository, AttackStateRepository

class InMemoryEventStore(EventStore):
    def __init__(self):
        self._events: Dict[str, PersistentEvent] = {}
        self._lock = asyncio.Lock()

    def _key(self, org_id, event_id):
        return f"{org_id}:{event_id}"

    async def add_event(self, event: PersistentEvent):
        async with self._lock:
            self._events[self._key(event.org_id, event.event_id)] = event

    async def claim_next_event(self, worker_id: str, event_types: List[str], lease_duration_sec: int = 30) -> Optional[PersistentEvent]:
        from security.utils.clock import Clock
        async with self._lock:
            now = Clock.get_instance().now()
            for key, ev in self._events.items():
                if ev.event_type in event_types:
                    if ev.status in [EventState.PENDING, EventState.RETRY_WAIT] or (ev.status == EventState.CLAIMED and ev.lease_expires_at and now > ev.lease_expires_at):
                        ev.status = EventState.CLAIMED
                        ev.claimed_by = worker_id
                        ev.fencing_token = str(uuid.uuid4())
                        ev.lease_expires_at = now + timedelta(seconds=lease_duration_sec)
                        ev.updated_at = now
                        ev.attempt_count += 1
                        return ev
            return None

    async def renew_lease(self, org_id: str, event_id: str, worker_id: str, fencing_token: str, duration_sec: int = 30) -> bool:
        from security.utils.clock import Clock
        async with self._lock:
            ev = self._events.get(self._key(org_id, event_id))
            if not ev or ev.status != EventState.CLAIMED or ev.claimed_by != worker_id or ev.fencing_token != fencing_token:
                return False
            now = Clock.get_instance().now()
            ev.lease_expires_at = now + timedelta(seconds=duration_sec)
            ev.updated_at = now
            return True

    async def update_event_state(self, org_id: str, event_id: str, worker_id: str, fencing_token: str, state: EventState, error_msg: Optional[str] = None, fatal: bool = False) -> bool:
        from security.utils.clock import Clock
        async with self._lock:
            ev = self._events.get(self._key(org_id, event_id))
            if not ev or ev.claimed_by != worker_id or ev.fencing_token != fencing_token:
                return False
                
            now = Clock.get_instance().now()
            ev.status = state
            ev.updated_at = now
            if error_msg:
                ev.last_error = error_msg
                
            if state == EventState.FAILED:
                if fatal or ev.attempt_count >= 3:
                    ev.status = EventState.DEAD_LETTER
                else:
                    ev.status = EventState.RETRY_WAIT
                    ev.claimed_by = None
                    ev.fencing_token = None
                    ev.lease_expires_at = None
                    
            return True

    async def get_event(self, org_id: str, event_id: str) -> Optional[PersistentEvent]:
        async with self._lock:
            return self._events.get(self._key(org_id, event_id))

    async def requeue_dead_letter(self, org_id: str, event_id: str, requested_by: str, reason: str, max_requeues: int = 3) -> bool:
        from security.utils.clock import Clock
        from security.models.persistent_state import RequeueRecord
        async with self._lock:
            ev = self._events.get(self._key(org_id, event_id))
            if not ev or ev.status != EventState.DEAD_LETTER:
                return False
            
            if ev.requeue_count >= max_requeues:
                return False
                
            ev.requeue_count += 1
            now = Clock.get_instance().now()
            
            record = RequeueRecord(
                recovery_id=str(uuid.uuid4()),
                org_id=org_id,
                event_id=event_id,
                requested_by=requested_by,
                reason=reason,
                previous_state=str(ev.status.value),
                new_state=str(EventState.PENDING.value),
                timestamp=now,
                requeue_count=ev.requeue_count
            )
            ev.requeue_history.append(record)
            
            ev.status = EventState.PENDING
            ev.claimed_by = None
            ev.fencing_token = None
            ev.lease_expires_at = None
            ev.attempt_count = 0
            ev.updated_at = now
            return True

class InMemoryAgentStateRepository(AgentStateRepository):
    pass
class InMemoryDetectionContextRepository(DetectionContextRepository):
    pass
class InMemoryAttackStateRepository(AttackStateRepository):
    pass
