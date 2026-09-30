import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from security.engine.agent_controller import WorkerType, WorkerState, AgentState

class WorkerHealth(BaseModel):
    worker_id: str
    worker_type: WorkerType
    state: WorkerState
    last_heartbeat: Optional[datetime] = None
    last_started: Optional[datetime] = None
    last_stopped: Optional[datetime] = None
    events_processed: int = 0
    events_failed: int = 0
    queue_size: int = 0
    queue_capacity: int = 0
    restart_count: int = 0
    last_error: Optional[str] = None
    last_error_at: Optional[datetime] = None
    healthy: bool = False
    degraded: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AgentHealthSnapshot(BaseModel):
    agent_state: AgentState
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    workers: List[WorkerHealth] = Field(default_factory=list)
    healthy_workers: int = 0
    degraded_workers: int = 0
    stale_workers: int = 0
    failed_workers: int = 0
    total_queue_depth: int = 0
    total_queue_capacity: int = 0
    queue_utilization: float = 0.0
    restart_count: int = 0
    events_processed: int = 0
    events_failed: int = 0
    health_reason: Optional[str] = None

class AgentHealthMonitor:
    def __init__(self, heartbeat_timeout: int = 15):
        self.heartbeat_timeout = heartbeat_timeout

    def check_worker_stale(self, worker_health: WorkerHealth) -> bool:
        if worker_health.state not in (WorkerState.RUNNING, WorkerState.DEGRADED):
            return False
        if not worker_health.last_heartbeat:
            return False
        
        delta = (datetime.now(timezone.utc) - worker_health.last_heartbeat).total_seconds()
        return delta > self.heartbeat_timeout

    def classify_worker_health(self, worker, health: WorkerHealth) -> WorkerHealth:
        # Check if stale
        is_stale = self.check_worker_stale(health)
        if is_stale:
            # We don't mutate the worker state here, just report it
            pass
        return health

    def generate_snapshot(self, agent_state: AgentState, workers: List[Any], events_processed: int, events_failed: int) -> AgentHealthSnapshot:
        snapshot = AgentHealthSnapshot(agent_state=agent_state, events_processed=events_processed, events_failed=events_failed)
        
        for w in workers:
            w_health = w.get_health()
            is_stale = self.check_worker_stale(w_health)
            if is_stale:
                snapshot.stale_workers += 1
            elif w_health.state == WorkerState.FAILED:
                snapshot.failed_workers += 1
            elif w_health.degraded:
                snapshot.degraded_workers += 1
            elif w_health.healthy:
                snapshot.healthy_workers += 1
            
            snapshot.workers.append(w_health)
            snapshot.total_queue_depth += w_health.queue_size
            snapshot.total_queue_capacity += w_health.queue_capacity
            snapshot.restart_count += w_health.restart_count
            
        if snapshot.total_queue_capacity > 0:
            snapshot.queue_utilization = snapshot.total_queue_depth / snapshot.total_queue_capacity
            
        # Determine overall agent state based on workers
        critical_types = {WorkerType.EVENT_INGESTION, WorkerType.DETECTION_CORRELATION}
        critical_failed = any(w.worker_type in critical_types and (w.state == WorkerState.FAILED or self.check_worker_stale(w)) for w in snapshot.workers)
        
        if critical_failed and agent_state not in (AgentState.STOPPED, AgentState.STOPPING):
            snapshot.agent_state = AgentState.FAILED
            snapshot.health_reason = "Critical worker failed or stale"
        elif snapshot.failed_workers > 0 or snapshot.stale_workers > 0 or snapshot.degraded_workers > 0:
            if snapshot.agent_state not in (AgentState.STOPPED, AgentState.STOPPING, AgentState.FAILED):
                snapshot.agent_state = AgentState.DEGRADED
                snapshot.health_reason = "Workers degraded/failed/stale"
                
        return snapshot
