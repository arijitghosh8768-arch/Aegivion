from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid

class EventState(str, Enum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRY_WAIT = "RETRY_WAIT"
    DEAD_LETTER = "DEAD_LETTER"

class RequeueRecord(BaseModel):
    recovery_id: str
    org_id: str
    event_id: str
    requested_by: str
    reason: str
    previous_state: str
    new_state: str
    timestamp: datetime
    requeue_count: int

class PersistentEvent(BaseModel):
    event_id: str
    org_id: str
    correlation_id: str = ""
    event_type: str = "UNKNOWN"
    payload: Dict[str, Any] = Field(default_factory=dict)
    source: str = "UNKNOWN"
    provenance: List[str] = Field(default_factory=list)
    status: EventState = EventState.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    claimed_by: Optional[str] = None
    fencing_token: Optional[str] = None
    lease_expires_at: Optional[datetime] = None
    attempt_count: int = 0
    last_error: Optional[str] = None
    requeue_count: int = 0
    requeue_history: List[RequeueRecord] = Field(default_factory=list)

class PersistentAgentState(BaseModel):
    organization_id: str
    state: str = "STOPPED"
    
class PersistentWorkerState(BaseModel):
    worker_id: str
    state: str = "STOPPED"

class PersistentDetectionContext(BaseModel):
    org_id: str
    events: list = []
    detections: list = []
    
class PersistentAttackState(BaseModel):
    org_id: str
    state_data: dict = {}
