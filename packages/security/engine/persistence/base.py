from abc import ABC, abstractmethod
from typing import List, Optional
from security.models.persistent_state import PersistentEvent, EventState

class EventStore(ABC):
    @abstractmethod
    async def add_event(self, event: PersistentEvent):
        pass
    
    @abstractmethod
    async def claim_next_event(self, worker_id: str, event_types: List[str], lease_duration_sec: int = 30) -> Optional[PersistentEvent]:
        pass

    @abstractmethod
    async def renew_lease(self, org_id: str, event_id: str, worker_id: str, fencing_token: str, duration_sec: int = 30) -> bool:
        pass

    @abstractmethod
    async def update_event_state(self, org_id: str, event_id: str, worker_id: str, fencing_token: str, state: EventState, error_msg: Optional[str] = None, fatal: bool = False) -> bool:
        pass

    @abstractmethod
    async def get_event(self, org_id: str, event_id: str) -> Optional[PersistentEvent]:
        pass

    @abstractmethod
    async def requeue_dead_letter(self, org_id: str, event_id: str, requested_by: str, reason: str, max_requeues: int = 3) -> bool:
        pass
        
class AgentStateRepository(ABC):
    pass
class DetectionContextRepository(ABC):
    pass
class AttackStateRepository(ABC):
    pass
