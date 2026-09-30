from typing import List, Optional
from abc import ABC, abstractmethod
from security.models.distributed_health import WorkerIdentity, HealthState
from security.utils.clock import Clock

class WorkerHealthRepository(ABC):
    @abstractmethod
    async def register_worker(self, worker: WorkerIdentity) -> bool:
        pass
        
    @abstractmethod
    async def heartbeat(self, worker_id: str, updates: dict) -> bool:
        pass
        
    @abstractmethod
    async def get_worker(self, worker_id: str) -> Optional[WorkerIdentity]:
        pass
        
    @abstractmethod
    async def list_workers(self, state: Optional[str] = None) -> List[WorkerIdentity]:
        pass
        
    @abstractmethod
    async def mark_stale(self, worker_id: str) -> bool:
        pass
        
    @abstractmethod
    async def mark_failed(self, worker_id: str) -> bool:
        pass
        
    @abstractmethod
    async def update_state(self, worker_id: str, state: str) -> bool:
        pass

class InMemoryWorkerHealthRepository(WorkerHealthRepository):
    def __init__(self):
        self._workers = {}  # worker_id -> WorkerIdentity
        
    async def register_worker(self, worker: WorkerIdentity) -> bool:
        if worker.worker_id not in self._workers:
            self._workers[worker.worker_id] = worker
        else:
            # Update running worker details if it exists but don't overwrite if it was a failure
            existing = self._workers[worker.worker_id]
            if existing.state not in (HealthState.FAILED, HealthState.STALE):
                self._workers[worker.worker_id] = worker
        return True
        
    async def heartbeat(self, worker_id: str, updates: dict) -> bool:
        if worker_id not in self._workers:
            return False
            
        worker = self._workers[worker_id]
        now = Clock.get_instance().now()
        worker.last_heartbeat = now
        worker.updated_at = now
        
        for k, v in updates.items():
            if hasattr(worker, k):
                setattr(worker, k, v)
                
        return True
        
    async def get_worker(self, worker_id: str) -> Optional[WorkerIdentity]:
        return self._workers.get(worker_id)
        
    async def list_workers(self, state: Optional[str] = None) -> List[WorkerIdentity]:
        if state:
            return [w for w in self._workers.values() if w.state == state]
        return list(self._workers.values())
        
    async def mark_stale(self, worker_id: str) -> bool:
        return await self.update_state(worker_id, HealthState.STALE)
        
    async def mark_failed(self, worker_id: str) -> bool:
        return await self.update_state(worker_id, HealthState.FAILED)
        
    async def update_state(self, worker_id: str, state: str) -> bool:
        if worker_id in self._workers:
            self._workers[worker_id].state = state
            self._workers[worker_id].updated_at = Clock.get_instance().now()
            return True
        return False
