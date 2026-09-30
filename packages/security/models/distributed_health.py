from typing import Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class HealthState(str):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    RECOVERING = "RECOVERING"

class WorkerIdentity(BaseModel):
    node_id: str
    worker_id: str
    worker_type: str
    process_id: Optional[str] = None
    started_at: datetime
    last_heartbeat: datetime
    last_processed_event: Optional[str] = None
    state: str = HealthState.HEALTHY
    queue_depth: int = 0
    queue_capacity: int = 0
    restart_count: int = 0
    failure_count: int = 0
    lease_count: int = 0
    events_processed: int = 0
    events_failed: int = 0
    retry_wait_count: int = 0
    dead_letter_count: int = 0
    updated_at: datetime

class NodeHealth(BaseModel):
    node_id: str
    state: str = HealthState.UNKNOWN
    worker_count: int = 0
    healthy_workers: int = 0
    degraded_workers: int = 0
    stale_workers: int = 0
    failed_workers: int = 0
    queue_depth: int = 0
    queue_capacity: int = 0
    queue_utilization: float = 0.0
    last_heartbeat: datetime
    restart_count: int = 0
    failure_count: int = 0
    updated_at: datetime

class DistributedHealthSnapshot(BaseModel):
    timestamp: datetime
    nodes: List[NodeHealth] = Field(default_factory=list)
    total_workers: int = 0
    healthy_workers: int = 0
    degraded_workers: int = 0
    stale_workers: int = 0
    failed_workers: int = 0
    total_queue_depth: int = 0
    total_queue_capacity: int = 0
    queue_utilization: float = 0.0
    healthy_capacity: int = 0
    degraded_capacity: int = 0
    failed_capacity: int = 0
    retry_wait_count: int = 0
    dead_letter_count: int = 0
    overall_state: str = HealthState.UNKNOWN
    health_reason: Optional[str] = None
