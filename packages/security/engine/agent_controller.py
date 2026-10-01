import asyncio
import uuid
import logging
from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class AgentState(str, Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    STOPPING = "STOPPING"
    FAILED = "FAILED"

class WorkerState(str, Enum):
    CREATED = "CREATED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"

class WorkerType(str, Enum):
    EVENT_INGESTION = "EVENT_INGESTION"
    DETECTION_CORRELATION = "DETECTION_CORRELATION"
    ACTIVATION_RISK = "ACTIVATION_RISK"
    RESPONSE_VERIFICATION = "RESPONSE_VERIFICATION"

class EventPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    NORMAL = "NORMAL"
    LOW = "LOW"

class EventSource(str, Enum):
    CLOUD = "CLOUD"
    DIGITAL_TWIN = "DIGITAL_TWIN"
    DETECTION = "DETECTION"
    ACTIVATION = "ACTIVATION"
    RESPONSE = "RESPONSE"
    VERIFICATION = "VERIFICATION"
    SYSTEM = "SYSTEM"

class AgentMode(str, Enum):
    STOPPED = "STOPPED"
    OBSERVE_ONLY = "OBSERVE_ONLY"
    CONTROLLED_RESPONSE = "CONTROLLED_RESPONSE"

class AgentEvent(BaseModel):
    event_id: str
    organization_id: str
    event_type: str
    occurred_at: datetime
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: EventSource
    correlation_id: str
    payload: Dict[str, Any]
    priority: EventPriority = EventPriority.NORMAL
    causation_id: Optional[str] = None
    trace_id: Optional[str] = None
    provenance: List[str] = Field(default_factory=list)



class AgentWorker:
    def __init__(self, worker_id: str, worker_type: WorkerType, organization_id: str):
        self.worker_id = worker_id
        self.worker_type = worker_type
        self.organization_id = organization_id
        self.state = WorkerState.CREATED
        self.started_at: Optional[datetime] = None
        self.stopped_at: Optional[datetime] = None
        self.last_heartbeat_at: Optional[datetime] = None
        self.processed_count = 0
        self.failed_count = 0
        self.restart_count = 0
        self.last_error: Optional[str] = None
        self.last_error_at: Optional[datetime] = None
        self.is_critical = True

    async def start(self):
        if self.state not in (WorkerState.CREATED, WorkerState.STOPPED, WorkerState.FAILED):
            raise ValueError(f"Cannot start from {self.state}")
        self.state = WorkerState.STARTING
        # Subclass implementation here
        self.state = WorkerState.RUNNING
        self.started_at = datetime.now(timezone.utc)
        self.heartbeat()

    async def stop(self):
        if self.state not in (WorkerState.RUNNING, WorkerState.DEGRADED, WorkerState.FAILED):
            raise ValueError(f"Cannot stop from {self.state}")
        self.state = WorkerState.STOPPING
        # Subclass implementation here
        self.state = WorkerState.STOPPED

    async def run(self):
        pass

    def heartbeat(self):
        self.last_heartbeat_at = datetime.now(timezone.utc)

    def get_health(self):
        from security.engine.agent_health import WorkerHealth
        return WorkerHealth(
            worker_id=self.worker_id,
            worker_type=self.worker_type,
            state=self.state,
            last_heartbeat=self.last_heartbeat_at,
            last_started=self.started_at,
            last_stopped=self.stopped_at,
            events_processed=self.processed_count,
            events_failed=self.failed_count,
            queue_size=0,
            queue_capacity=0,
            restart_count=self.restart_count,
            last_error=self.last_error,
            last_error_at=self.last_error_at,
            healthy=self.state == WorkerState.RUNNING,
            degraded=self.state == WorkerState.DEGRADED,
        )

    async def handle_event(self, event: AgentEvent):
        raise NotImplementedError()


class AegivionAgentController:
    """
    Phase 6A: Deterministic State Machine for Agent Orchestration
    """
    def __init__(self, max_queue_size: int = 1000, organization_id: Optional[str] = None, mode: AgentMode = AgentMode.OBSERVE_ONLY, event_store=None, detection_context_repo=None, attack_state_repo=None, digital_twin=None):
        self.agent_id = f"AGENT-{uuid.uuid4().hex[:8]}"
        self.organization_id = organization_id
        self.mode = mode
        self.event_store = event_store
        self.detection_context_repo = detection_context_repo
        self.attack_state_repo = attack_state_repo
        # Phase 5A: optional SecurityDigitalTwin for pre-detection twin updates.
        # When provided, update_from_event() is called before worker dispatch.
        # When None, the controller operates without twin context (all tests pass).
        self.digital_twin = digital_twin
        self.state = AgentState.STOPPED
        self.started_at: Optional[datetime] = None
        self.last_heartbeat_at: Optional[datetime] = None
        
        self.max_queue_size = max_queue_size
        self._queue: Optional[asyncio.Queue] = None
        
        self._workers: Dict[str, AgentWorker] = {}
        self._seen_events: set = set()
        
        from security.engine.agent_health import AgentHealthMonitor
        from security.engine.agent_recovery import AgentRecoveryManager
        self.health_monitor = AgentHealthMonitor()
        self.recovery_manager = AgentRecoveryManager()
        self._health_task: Optional[asyncio.Task] = None
        
        # Metrics
        self.events_received = 0
        self.events_accepted = 0
        self.events_rejected = 0
        self.events_processed = 0
        self.events_failed = 0
        self.events_deduplicated = 0
        
        self._loop_task: Optional[asyncio.Task] = None
        
        self.routing_table = {
            "CLOUD_EVENT": WorkerType.EVENT_INGESTION,
            "ASSET_UPDATED": WorkerType.EVENT_INGESTION,
            
            "SECURITY_EVENT_INGESTED": WorkerType.DETECTION_CORRELATION,
            
            "DETECTION_COMPLETED": WorkerType.ACTIVATION_RISK,
            
            "ACTIVATION_ANALYSIS_REQUESTED": WorkerType.ACTIVATION_RISK,
            "ACTIVATION_ANALYSIS_COMPLETED": WorkerType.RESPONSE_VERIFICATION,
            "PREDICTION_COMPLETED": WorkerType.RESPONSE_VERIFICATION,
            
            "RESPONSE_ANALYSIS_REQUESTED": WorkerType.RESPONSE_VERIFICATION,
            "RESPONSE_RECOMMENDED": WorkerType.RESPONSE_VERIFICATION,
            "RESPONSE_POLICY_EVALUATED": WorkerType.RESPONSE_VERIFICATION,
            "RESPONSE_EXECUTION_REQUESTED": WorkerType.RESPONSE_VERIFICATION,
            "RESPONSE_VERIFICATION_COMPLETED": WorkerType.RESPONSE_VERIFICATION,
            
            "PIPELINE_ERROR": WorkerType.EVENT_INGESTION, # Default fallback
        }

    def register_worker(self, worker: AgentWorker):
        if worker.worker_id in self._workers:
            raise ValueError(f"Worker {worker.worker_id} already registered.")
        if hasattr(worker, 'set_emit_callback'):
            worker.set_emit_callback(self.submit_event)
        if hasattr(worker, 'event_store') and self.event_store:
            worker.event_store = self.event_store
        if hasattr(worker, 'detection_context_repo') and self.detection_context_repo:
            worker.detection_context_repo = self.detection_context_repo
        if hasattr(worker, 'attack_state_repo') and self.attack_state_repo:
            worker.attack_state_repo = self.attack_state_repo
        self._workers[worker.worker_id] = worker

    def unregister_worker(self, worker_id: str):
        if worker_id in self._workers:
            del self._workers[worker_id]

    def get_worker(self, worker_id: str) -> Optional[AgentWorker]:
        return self._workers.get(worker_id)

    def list_workers(self) -> List[AgentWorker]:
        return list(self._workers.values())

    async def start(self):
        if self.state not in (AgentState.STOPPED, AgentState.FAILED):
            raise ValueError(f"Cannot start agent from state {self.state}")
            
        self.state = AgentState.STARTING
        self._queue = asyncio.Queue(maxsize=self.max_queue_size)
        self.started_at = datetime.now(timezone.utc)
        
        # Start workers
        for worker in self._workers.values():
            try:
                await worker.start()
            except Exception as e:
                logger.error(f"Failed to start worker {worker.worker_id}: {e}")
                worker.state = WorkerState.FAILED
                if worker.is_critical:
                    self.state = AgentState.FAILED
                    raise RuntimeError(f"Critical worker {worker.worker_id} failed to start.")
                    
        # Verify worker heartbeats before running
        await asyncio.sleep(0.5)
        for worker in self._workers.values():
            if worker.is_critical and (not worker.last_heartbeat_at or worker.state != WorkerState.RUNNING):
                self.state = AgentState.FAILED
                raise RuntimeError(f"Critical worker {worker.worker_id} failed heartbeat verification on startup.")

        self.state = AgentState.RUNNING
        self._loop_task = asyncio.create_task(self._event_loop())
        self._health_task = asyncio.create_task(self._health_monitor_loop())
        self.heartbeat()

    async def stop(self):
        if self.state not in (AgentState.RUNNING, AgentState.DEGRADED, AgentState.FAILED):
            return # Idempotent stop
            
        self.state = AgentState.STOPPING
        
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass

        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
                
        for worker in self._workers.values():
            if worker.state in (WorkerState.RUNNING, WorkerState.DEGRADED):
                try:
                    await worker.stop()
                except Exception as e:
                    logger.error(f"Error stopping worker {worker.worker_id}: {e}")
                
        self.state = AgentState.STOPPED

    async def _health_monitor_loop(self):
        while self.state in (AgentState.RUNNING, AgentState.DEGRADED):
            try:
                await asyncio.sleep(5.0)  # Check interval
                
                # Check stale and failed
                for worker in self._workers.values():
                    if worker.state == WorkerState.FAILED or self.health_monitor.check_worker_stale(worker.get_health()):
                        logger.warning(f"Worker {worker.worker_id} detected as FAILED or STALE. Attempting recovery...")
                        success = await self.recovery_manager.attempt_restart(worker)
                        if success:
                            # Recovery emitted
                            pass
                        else:
                            # Not recovered
                            pass
                            
                # Generate snapshot to update agent state
                snapshot = self.get_health()
                if self.state != snapshot.agent_state and self.state not in (AgentState.STOPPED, AgentState.STOPPING):
                    logger.info(f"Agent state changed to {snapshot.agent_state} due to worker health.")
                    self.state = snapshot.agent_state
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health monitor loop error: {e}")
                
    def get_health(self):
        return self.health_monitor.generate_snapshot(
            self.state, 
            list(self._workers.values()),
            self.events_processed, 
            self.events_failed
        )

    def get_worker_health(self, worker_id: str):
        worker = self.get_worker(worker_id)
        if worker:
            return worker.get_health()
        return None

    def heartbeat(self):
        if self.state == AgentState.RUNNING:
            self.last_heartbeat_at = datetime.now(timezone.utc)
            
            # Check worker health
            degraded = False
            for worker in self._workers.values():
                hw = worker.get_health()
                if not hw.healthy:
                    if worker.is_critical:
                        degraded = True
                        
            if degraded:
                self.state = AgentState.DEGRADED

    async def submit_event(self, event: AgentEvent) -> str:
        self.events_received += 1
        
        if self.state not in (AgentState.RUNNING, AgentState.DEGRADED):
            self.events_rejected += 1
            return "AGENT_NOT_RUNNING"
            
        # AI Safety boundary check
        if event.source in (EventSource.SYSTEM, "AI_DIRECT", "LLM_DIRECT", "FRONTEND_DIRECT"):
            if event.source != EventSource.SYSTEM: # Allow SYSTEM, reject others
                self.events_rejected += 1
                return "UNAUTHORIZED_SOURCE"
                
        # Correlation Generation
        if not event.correlation_id:
            event.correlation_id = f"CORR-{uuid.uuid4().hex[:8]}"
            
        # Tenant Isolation Check
        if self.organization_id and event.organization_id != self.organization_id:
            self.events_rejected += 1
            return "TENANT_MISMATCH"
            
        # Deduplication
        if event.event_id in self._seen_events:
            self.events_deduplicated += 1
            return "DUPLICATE_EVENT"
            
        self._seen_events.add(event.event_id)
        
        if self.event_store:
            from security.models.persistent_state import PersistentEvent
            pe = PersistentEvent(
                event_id=event.event_id,
                correlation_id=event.correlation_id,
                org_id=event.organization_id,
                event_type=event.event_type,
                payload=event.payload,
                source=event.source.value,
                provenance=event.provenance
            )
            await self.event_store.add_event(pe)
        else:
            if self._queue.full():
                self.events_rejected += 1
                return "QUEUE_FULL"
                
            await self._queue.put(event)
            
        self.events_accepted += 1
        return "ACCEPTED"

    async def _event_loop(self):
        while self.state in (AgentState.RUNNING, AgentState.DEGRADED):
            if self.event_store:
                await asyncio.sleep(1.0)
                self.heartbeat()
                continue
                
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                self.heartbeat()
                continue
            except asyncio.CancelledError:
                break
                
            # Process event
            await self._route_and_process(event)
            self._queue.task_done()

    async def _route_and_process(self, event: AgentEvent):
        # Routing
        if event.event_type == "HEARTBEAT":
            self.heartbeat()
            self.events_processed += 1
            return
            
        if event.event_type == "SHUTDOWN":
            await self.stop()
            self.events_processed += 1
            return

        target_type = self.routing_table.get(event.event_type)
        if not target_type:
            self.events_rejected += 1
            return
            
        # Find matching worker
        target_worker = next((w for w in self._workers.values() if w.worker_type == target_type), None)
        
        if not target_worker:
            self.events_failed += 1
            return
            
        if target_worker.state not in (WorkerState.RUNNING, WorkerState.DEGRADED):
            self.events_failed += 1
            return
            
        # Tenant check on worker
        if target_worker.organization_id != event.organization_id:
            self.events_failed += 1
            return

        # Phase 5A: Update the Digital Twin BEFORE routing to workers.
        # SecurityDigitalTwin decides what the event means and what state changes;
        # TwinPersistenceRepository handles how it is persisted.
        # Workers receive an already-current twin state.
        if self.digital_twin is not None:
            try:
                self.digital_twin.update_from_event(event)
            except Exception as twin_err:
                # Twin update failures are non-fatal: log and continue processing.
                logger.warning(
                    f"[AgentController] Twin update failed for event {event.event_id}: {twin_err}"
                )
            
        try:
            await target_worker.handle_event(event)
            target_worker.processed_count += 1
            self.events_processed += 1
            target_worker.heartbeat()
        except Exception as e:
            logger.error(f"Worker {target_worker.worker_id} failed to process event {event.event_id}: {e}")
            target_worker.failed_count += 1
            self.events_failed += 1
            target_worker.state = WorkerState.FAILED
            if target_worker.is_critical:
                self.state = AgentState.DEGRADED
