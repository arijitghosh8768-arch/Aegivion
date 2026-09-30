from sqlalchemy import Column, String, JSON, DateTime, Integer, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class PersistentEventModel(Base):
    __tablename__ = 'persistent_events'
    
    event_id = Column(String, primary_key=True)
    org_id = Column(String, primary_key=True)
    correlation_id = Column(String, default="")
    event_type = Column(String, default="UNKNOWN")
    payload = Column(JSON, default=dict)
    source = Column(String, default="UNKNOWN")
    provenance = Column(JSON, default=list) # Stored as JSON array
    status = Column(String, index=True) # EventState
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    claimed_by = Column(String, nullable=True, index=True)
    fencing_token = Column(String, nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    attempt_count = Column(Integer, default=0)
    last_error = Column(String, nullable=True)
    requeue_count = Column(Integer, default=0)
    
class RequeueRecordModel(Base):
    __tablename__ = 'requeue_records'
    
    recovery_id = Column(String, primary_key=True)
    org_id = Column(String, index=True)
    event_id = Column(String, index=True)
    requested_by = Column(String)
    reason = Column(String)
    previous_state = Column(String)
    new_state = Column(String)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    requeue_count = Column(Integer)

class PersistentAgentStateModel(Base):
    __tablename__ = 'agent_states'
    
    organization_id = Column(String, primary_key=True)
    state = Column(String, default="STOPPED")

class PersistentWorkerStateModel(Base):
    __tablename__ = 'worker_states'
    
    worker_id = Column(String, primary_key=True)
    state = Column(String, default="STOPPED")

class PersistentDetectionContextModel(Base):
    __tablename__ = 'detection_contexts'
    
    org_id = Column(String, primary_key=True)
    events = Column(JSON, default=list)
    detections = Column(JSON, default=list)

class PersistentAttackStateModel(Base):
    __tablename__ = 'attack_states'
    
    org_id = Column(String, primary_key=True)
    state_data = Column(JSON, default=dict)
