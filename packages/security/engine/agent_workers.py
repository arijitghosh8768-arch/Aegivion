import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import uuid

class WorkerValidationError(Exception):
    """Raised for malformed events or unrecoverable validation failures."""
    pass

class WorkerTransientError(Exception):
    """Raised for temporary dependency or runtime failures."""
    pass

from app.models.security_event import SecurityEvent
from security.engine.agent_controller import (
    AgentWorker, WorkerState, WorkerType, AgentEvent, EventSource, AgentMode
)

from security.engine.detectors.credential_compromise_adapter import CredentialCompromiseAdapter
from security.engine.detectors.data_exfiltration_adapter import DataExfiltrationAdapter
from security.engine.detectors.ransomware_destruction import RansomwareDestructionDetector
from security.engine.detection_context import DetectionContext
from security.engine.detection_correlation import DetectionCorrelationEngine

from security.engine.temporal_attack_progression import TemporalAttackProgressionEngine, TemporalEvidence
from security.engine.dynamic_attack_path import DynamicAttackPathRiskEngine
from security.engine.unified_attack_activation import UnifiedAttackActivationEngine, UnifiedEvidence
from security.engine.next_stage_prediction import NextStagePredictionEngine
from security.engine.attack_state_tracker import SecurityAttackStateTracker, AttackState

from security.engine.what_if_simulation import WhatIfSimulationEngine, SimulationScenario, SimulationState
from security.engine.minimum_impact_response import MinimumImpactResponseOptimizer, ResponseCandidate
from security.engine.response_safety_policy import ResponseSafetyPolicyEngine, ResponseSafetyPolicy, ResponseTarget, ResponseDecision
from security.engine.execution_orchestrator import ExecutionOrchestrator, ExecutionRequest
from security.engine.execution_contract import PrivilegeTarget, PrivilegeExpectedState

logger = logging.getLogger(__name__)

class AsyncQueueWorker(AgentWorker):
    def __init__(self, worker_id: str, worker_type: WorkerType, organization_id: str, max_queue_size: int = 500, mode: AgentMode = AgentMode.OBSERVE_ONLY, node_id: str = "n1", health_repository=None):
        super().__init__(worker_id, worker_type, organization_id)
        self.node_id = node_id
        self.health_repository = health_repository
        self.max_queue_size = max_queue_size
        self.mode = mode
        self._queue: Optional[asyncio.Queue] = None
        self._run_task: Optional[asyncio.Task] = None
        self.controller = None # Will be set by controller if needed, but we should just emit events to a callback or return them.
        self.emit_callback = None
        self.event_store = None
        self.event_types = self._get_event_types_for_worker(worker_type)

    def _get_event_types_for_worker(self, worker_type: WorkerType) -> List[str]:
        if worker_type == WorkerType.EVENT_INGESTION:
            return ["CLOUD_EVENT", "API_EVENT"]
        elif worker_type == WorkerType.DETECTION_CORRELATION:
            return ["SECURITY_EVENT_INGESTED"]
        elif worker_type == WorkerType.ACTIVATION_RISK:
            return ["CORRELATION_COMPLETED"]
        elif worker_type == WorkerType.RESPONSE_VERIFICATION:
            return ["ATTACK_ACTIVATED"]
        return []

    def set_emit_callback(self, callback):
        self.emit_callback = callback

    async def emit(self, event: AgentEvent):
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
        elif self.emit_callback:
            res = self.emit_callback(event)
            if asyncio.iscoroutine(res):
                await res

    async def start(self, preserve_queue: bool = False):
        if self.state not in (WorkerState.CREATED, WorkerState.STOPPED, WorkerState.FAILED):
            raise ValueError(f"Cannot start from {self.state}")
        
        self.state = WorkerState.STARTING
        if not preserve_queue or self._queue is None:
            self._queue = asyncio.Queue(maxsize=self.max_queue_size)
        self.state = WorkerState.RUNNING
        
        from security.utils.clock import Clock
        self.started_at = Clock.get_instance().now()
        
        if self.health_repository:
            from security.models.distributed_health import WorkerIdentity, HealthState
            w = WorkerIdentity(
                node_id=self.node_id,
                worker_id=self.worker_id,
                worker_type=self.worker_type.value if hasattr(self.worker_type, 'value') else str(self.worker_type),
                started_at=self.started_at,
                last_heartbeat=self.started_at,
                updated_at=self.started_at,
                queue_capacity=self.max_queue_size
            )
            await self.health_repository.register_worker(w)
            
        await self.heartbeat_async()
        
        self._run_task = asyncio.create_task(self.run())

    async def heartbeat_async(self):
        self.heartbeat() # local health heartbeat
        if self.health_repository:
            state_str = self.state.value if hasattr(self.state, 'value') else str(self.state)
            health_state = "HEALTHY" if state_str == "RUNNING" else "FAILED" if state_str == "FAILED" else state_str
            await self.health_repository.heartbeat(self.worker_id, {
                "queue_depth": self._queue.qsize() if self._queue else 0,
                "events_processed": self.processed_count,
                "events_failed": self.failed_count,
                "restart_count": self.restart_count,
                "state": health_state
            })

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
            queue_size=self._queue.qsize() if self._queue else 0,
            queue_capacity=self.max_queue_size,
            restart_count=self.restart_count,
            last_error=self.last_error,
            last_error_at=self.last_error_at,
            healthy=self.state == WorkerState.RUNNING,
            degraded=self.state == WorkerState.DEGRADED,
        )

    async def stop(self):
        if self.state not in (WorkerState.RUNNING, WorkerState.DEGRADED, WorkerState.FAILED):
            return
            
        self.state = WorkerState.STOPPING
        if self._run_task:
            self._run_task.cancel()
            try:
                await self._run_task
            except asyncio.CancelledError:
                pass
        self.state = WorkerState.STOPPED
        self.stopped_at = datetime.now(timezone.utc)

    async def handle_event(self, event: AgentEvent):
        if self.state not in (WorkerState.RUNNING, WorkerState.DEGRADED):
            raise RuntimeError(f"Worker {self.worker_id} is not accepting events in state {self.state}")
            
        if self._queue.full():
            await self.emit(AgentEvent(
                event_id=f"ERR-{uuid.uuid4().hex[:8]}",
                organization_id=self.organization_id,
                event_type="QUEUE_FULL",
                occurred_at=datetime.now(timezone.utc),
                source=EventSource.SYSTEM,
                correlation_id=event.correlation_id,
                payload={"worker": self.worker_id, "capacity": self.max_queue_size},
                provenance=event.provenance + [f"Queue pressure in {self.worker_type}"]
            ))
            raise RuntimeError(f"Worker {self.worker_id} internal queue is full (Backpressure)")
            
        await self._queue.put(event)

    async def run(self):
        from security.models.persistent_state import EventState
        while self.state in (WorkerState.RUNNING, WorkerState.DEGRADED):
            event = None
            event_record = None
            if self.event_store:
                event_record = await self.event_store.claim_next_event(self.worker_id, self.event_types)
                if not event_record:
                    await asyncio.sleep(0.5)
                    await self.heartbeat_async()
                    continue
                
                event = AgentEvent(
                    event_id=event_record.event_id,
                    organization_id=event_record.org_id,
                    event_type=event_record.event_type,
                    occurred_at=event_record.created_at,
                    source=EventSource(event_record.source),
                    correlation_id=event_record.correlation_id,
                    payload=event_record.payload,
                    provenance=event_record.provenance
                )
            else:
                try:
                    event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    await self.heartbeat_async()
                    continue
                except asyncio.CancelledError:
                    break
                
            lease_task = None
            if self.event_store and event_record and event_record.fencing_token:
                async def renewer():
                    while True:
                        await asyncio.sleep(15)
                        try:
                            renewed = await self.event_store.renew_lease(event_record.org_id, event_record.event_id, self.worker_id, event_record.fencing_token, 30)
                            if not renewed:
                                break
                        except Exception:
                            pass
                lease_task = asyncio.create_task(renewer())

            try:
                await self.process_event(event)
                self.processed_count += 1
                if self.event_store:
                    await self.event_store.update_event_state(event_record.org_id, event.event_id, self.worker_id, event_record.fencing_token, EventState.COMPLETED)
            except asyncio.CancelledError:
                break
            except WorkerValidationError as e:
                logger.error(f"Worker {self.worker_id} validation error on event {event.event_id}: {e}")
                self.failed_count += 1
                if self.event_store:
                    await self.event_store.update_event_state(
                        event_record.org_id, event.event_id, self.worker_id, event_record.fencing_token, 
                        EventState.FAILED, str(e), fatal=True
                    )
            except WorkerTransientError as e:
                logger.error(f"Worker {self.worker_id} transient error on event {event.event_id}: {e}")
                self.failed_count += 1
                if self.event_store:
                    await self.event_store.update_event_state(
                        event_record.org_id, event.event_id, self.worker_id, event_record.fencing_token, 
                        EventState.FAILED, str(e), fatal=False
                    )
            except Exception as e:
                logger.error(f"Worker {self.worker_id} encountered internal failure on event {event.event_id}: {e}")
                self.failed_count += 1
                if self.event_store:
                    # Generic internal errors could be retried up to max_retries, but we do not leak secrets
                    # We strip any potential secrets from the message
                    safe_error = str(e).replace(self.organization_id, "ORG_ID") if self.organization_id else str(e)
                    await self.event_store.update_event_state(
                        event_record.org_id, event.event_id, self.worker_id, event_record.fencing_token, 
                        EventState.FAILED, safe_error, fatal=False
                    )
                # Emit PIPELINE_ERROR
                await self.emit(AgentEvent(
                    event_id=f"ERR-{uuid.uuid4().hex[:8]}",
                    organization_id=self.organization_id,
                    event_type="PIPELINE_ERROR",
                    occurred_at=datetime.now(timezone.utc),
                    source=EventSource.SYSTEM,
                    correlation_id=event.correlation_id if event else "",
                    payload={"error": str(e), "failed_event": event.event_id if event else ""},
                    provenance=(event.provenance if event else []) + [f"Error in {self.worker_type.value}"]
                ))
            finally:
                if lease_task:
                    lease_task.cancel()
                    try:
                        await lease_task
                    except asyncio.CancelledError:
                        pass
                if not self.event_store and event:
                    self._queue.task_done()
                await self.heartbeat_async()

    async def process_event(self, event: AgentEvent):
        raise NotImplementedError()


class EventIngestionWorker(AsyncQueueWorker):
    def __init__(self, worker_id: str, organization_id: str, mode: AgentMode = AgentMode.OBSERVE_ONLY):
        super().__init__(worker_id, WorkerType.EVENT_INGESTION, organization_id, mode=mode)

    async def process_event(self, event: AgentEvent):
        # 1. Receive normalized event
        # 2. Validate org_id
        if event.organization_id != self.organization_id:
            raise ValueError("Tenant mismatch")
            
        # 3. Call existing ingestion (simulate or directly call)
        sec_event_id = event.payload.get("event_id", f"SEC-{uuid.uuid4().hex[:8]}")
        
        # Emit SECURITY_EVENT_INGESTED
        out_payload = {
            "security_event_id": sec_event_id,
            "provider": event.payload.get("provider", "aws"),
            "category": event.payload.get("category", "NETWORK"),
            "actor_id": event.payload.get("actor_id", "unknown"),
            "target_id": event.payload.get("target_id", "unknown"),
            "timestamp": event.payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "raw_payload": event.payload
        }
        
        new_event = AgentEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:8]}",
            organization_id=self.organization_id,
            event_type="SECURITY_EVENT_INGESTED",
            occurred_at=datetime.now(timezone.utc),
            source=EventSource.SYSTEM,
            correlation_id=event.correlation_id,
            payload=out_payload,
            provenance=event.provenance + ["EventIngestionWorker"]
        )
        await self.emit(new_event)


class DetectionCorrelationWorker(AsyncQueueWorker):
    def __init__(self, worker_id: str, organization_id: str, mode: AgentMode = AgentMode.OBSERVE_ONLY):
        super().__init__(worker_id, WorkerType.DETECTION_CORRELATION, organization_id, mode=mode)
        self.detectors = [
            CredentialCompromiseAdapter(),
            DataExfiltrationAdapter(),
            RansomwareDestructionDetector()
        ]
        self.context = DetectionContext(
            max_events_per_tenant=1000, 
            max_detections_per_tenant=500, 
            max_window_minutes=60
        )
        self.correlation_engine = DetectionCorrelationEngine()
        self.detection_context_repo = None

    async def process_event(self, event: AgentEvent):
        if event.event_type != "SECURITY_EVENT_INGESTED":
            return
            
        payload = event.payload
        self.context.add_event(self.organization_id, payload)
        
        # Optionally persist
        if self.detection_context_repo:
            await self.detection_context_repo.save_context(self.organization_id, {"events": self.context.get_events(self.organization_id), "detections": self.context.get_detections(self.organization_id)})
            
        sec_event = SecurityEvent(
            event_id=payload["security_event_id"],
            organization_id=self.organization_id,
            event_type=payload.get("category", "UNKNOWN"),
            timestamp=datetime.now(timezone.utc),
            source={"ip_address": "192.168.1.1"}, # Mock or parse
            action="mock_action",
            actor={"identity": payload.get("actor_id")}
        )
        
        twin_context = {"known_ips": [], "recent_failed_logins": 0}
        
        detections = []
        suspicious_count = 0
        for detector in self.detectors:
            result = detector.evaluate(sec_event, twin_context)
            res_dict = result.dict() if hasattr(result, "dict") else result.model_dump()
            
            if result.confidence_score > 0.5:
                suspicious_count += 1
                det_id = self.context.generate_detection_id(self.organization_id, sec_event.event_id, result.detector_name)
                res_dict["detection_id"] = det_id
                res_dict["event_id"] = sec_event.event_id
                res_dict["actor_id"] = payload.get("actor_id")
                
                self.context.add_detection(self.organization_id, res_dict)
                detections.append(res_dict)
                
                # Correlate
                related = self.context.get_context_for_correlation(self.organization_id, res_dict)
                corr = self.correlation_engine.correlate(self.organization_id, res_dict, related)
                if corr:
                    corr_payload = corr.dict() if hasattr(corr, "dict") else corr.model_dump()
                    corr_event = AgentEvent(
                        event_id=f"COR-{uuid.uuid4().hex[:8]}",
                        organization_id=self.organization_id,
                        event_type="CORRELATION_COMPLETED",
                        occurred_at=datetime.now(timezone.utc),
                        source=EventSource.SYSTEM,
                        correlation_id=event.correlation_id,
                        payload=corr_payload,
                        provenance=event.provenance + ["DetectionCorrelationWorker"]
                    )
                    await self.emit(corr_event)
                
        out_payload = {
            "security_event_id": sec_event.event_id,
            "detections": detections,
            "detector_count": len(self.detectors),
            "suspicious_count": suspicious_count
        }
        
        if suspicious_count > 0:
            new_event = AgentEvent(
                event_id=f"DET-{uuid.uuid4().hex[:8]}",
                organization_id=self.organization_id,
                event_type="DETECTION_COMPLETED",
                occurred_at=datetime.now(timezone.utc),
                source=EventSource.DETECTION,
                correlation_id=event.correlation_id,
                payload=out_payload,
                provenance=event.provenance + ["DetectionCorrelationWorker"]
            )
            await self.emit(new_event)


class ActivationRiskWorker(AsyncQueueWorker):
    def __init__(self, worker_id: str, organization_id: str, mode: AgentMode = AgentMode.OBSERVE_ONLY):
        super().__init__(worker_id, WorkerType.ACTIVATION_RISK, organization_id, mode=mode)
        self.temporal_engine = TemporalAttackProgressionEngine()
        self.dynamic_engine = DynamicAttackPathRiskEngine()
        self.unified_engine = UnifiedAttackActivationEngine()
        self.prediction_engine = NextStagePredictionEngine()
        self.state_tracker = SecurityAttackStateTracker()
        self.attack_state_repo = None

    async def process_event(self, event: AgentEvent):
        if event.event_type not in ["DETECTION_COMPLETED", "CORRELATION_COMPLETED"]:
            return
            
        payload = event.payload
        sequence_id = event.correlation_id or payload.get("security_event_id") or payload.get("correlation_id") or "UNKNOWN_SEQ"
        
        # Parse evidence from event
        threat_type = "UNKNOWN"
        confidence = 0.0
        
        if event.event_type == "DETECTION_COMPLETED":
            detections = payload.get("detections", [])
            if detections:
                threat_type = detections[0].get("attack_type", "UNKNOWN")
                confidence = detections[0].get("confidence_score", 0.0)
        elif event.event_type == "CORRELATION_COMPLETED":
            threat_type = payload.get("correlation_type", "UNKNOWN")
            confidence = payload.get("score", 0.0)
            
        # 1. Temporal Attack Progression
        temporal_ev_dict = {
            "event_id": sequence_id,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "category": threat_type
        }
        temp_result = self.temporal_engine.evaluate(self.organization_id, [temporal_ev_dict], window_minutes=60)
        
        # 2. Dynamic Path Risk
        path_nodes = [{"id": "entry1", "risk_score": 0.5}, {"id": "target1", "risk_score": 0.9}]
        path_edges = [{"source": "entry1", "target": "target1", "weight": 1.0}]
        path_result = self.dynamic_engine.calculate_risk(self.organization_id, path_nodes, path_edges)
        
        # 3. Unified Attack Activation
        unified_result = self.unified_engine.evaluate(
            organization_id=self.organization_id,
            path_risk_result=path_result,
            temporal_result=temp_result
        )
        
        # 4. Next-Stage Prediction
        prediction = self.prediction_engine.evaluate(
            organization_id=self.organization_id,
            temporal_result=temp_result,
            path_result=path_result,
            activation_result=unified_result
        )
        
        # 5. Continuous State Tracking
        preds_dict = prediction.dict() if hasattr(prediction, "dict") else prediction.model_dump()
        new_state_ctx = self.state_tracker.update_state(
            org_id=self.organization_id,
            sequence_id=sequence_id,
            temporal_score=temp_result.progression_score,
            risk_score=path_result.risk_score,
            activation_score=unified_result.activation_score,
            predictions=preds_dict.get("predictions", [])
        )
        
        if self.attack_state_repo:
            await self.attack_state_repo.save_state(self.organization_id, {"state": new_state_ctx.current_state.value, "transitions": [t.dict() if hasattr(t, "dict") else t.model_dump() for t in new_state_ctx.transitions]})
        
        out_payload = {
            "sequence_id": sequence_id,
            "attack_state": new_state_ctx.current_state.value,
            "temporal": temp_result.dict() if hasattr(temp_result, "dict") else temp_result.model_dump(),
            "path_risk": path_result.dict() if hasattr(path_result, "dict") else path_result.model_dump(),
            "unified": unified_result.dict() if hasattr(unified_result, "dict") else unified_result.model_dump(),
            "prediction": preds_dict,
            "state_transitions": [t.dict() if hasattr(t, "dict") else t.model_dump() for t in new_state_ctx.transitions]
        }
        
        new_event = AgentEvent(
            event_id=f"ACT-{uuid.uuid4().hex[:8]}",
            organization_id=self.organization_id,
            event_type="ACTIVATION_ANALYSIS_COMPLETED",
            occurred_at=datetime.now(timezone.utc),
            source=EventSource.ACTIVATION,
            correlation_id=event.correlation_id,
            payload=out_payload,
            provenance=event.provenance + ["ActivationRiskWorker"]
        )
        await self.emit(new_event)


class ResponseVerificationWorker(AsyncQueueWorker):
    def __init__(self, worker_id: str, organization_id: str, mode: AgentMode = AgentMode.OBSERVE_ONLY):
        super().__init__(worker_id, WorkerType.RESPONSE_VERIFICATION, organization_id, mode=mode)
        self.sim_engine = WhatIfSimulationEngine()
        self.optimizer = MinimumImpactResponseOptimizer()
        self.safety = ResponseSafetyPolicyEngine()
        self.orchestrator = ExecutionOrchestrator()

    async def process_event(self, event: AgentEvent):
        if event.event_type != "ACTIVATION_ANALYSIS_COMPLETED":
            return
            
        # In a real integration, the SimulationState would be pulled from a global
        # digital twin state. Here we mock an empty one for the worker orchestration.
        current_state = SimulationState(organization_id=self.organization_id)
        
        # We need the prediction result to generate candidates
        # We parse it from the payload
        from security.engine.next_stage_prediction import NextStagePredictionResult
        
        prediction_dict = event.payload.get("prediction", {})
        # create dummy if missing
        if "organization_id" not in prediction_dict:
            prediction_dict["organization_id"] = self.organization_id
        if "current_stage" not in prediction_dict:
            from security.engine.next_stage_prediction import AttackStage
            prediction_dict["current_stage"] = AttackStage.UNKNOWN
        if "predictions" not in prediction_dict:
            prediction_dict["predictions"] = []
        if "uncertainty" not in prediction_dict:
            prediction_dict["uncertainty"] = "HIGH"
        if "state" not in prediction_dict:
            prediction_dict["state"] = "COMPLETED"
            
        try:
            prediction_res = NextStagePredictionResult(**prediction_dict)
        except Exception:
            # Fallback
            from security.engine.next_stage_prediction import AttackStage
            prediction_res = NextStagePredictionResult(
                organization_id=self.organization_id,
                current_stage=AttackStage.UNKNOWN,
                predictions=[],
                uncertainty="HIGH",
                state="COMPLETED"
            )

        # 1. Generate Candidates & Optimize
        # optimizer.generate_candidates generates possible response actions based on state & prediction
        try:
            candidates = self.optimizer.generate_candidates(current_state, prediction_res)
            # Add a fallback candidate if none were generated so the pipeline doesn't stop
            if not candidates:
                from security.engine.minimum_impact_response import ResponseAction
                candidates.append(ResponseCandidate(
                    organization_id=self.organization_id,
                    action=ResponseAction.ISOLATE_NETWORK_PATH,
                    target_id="fallback",
                    rationale="Fallback isolation",
                    simulation_changes=[]
                ))
            
            optimizer_decision = self.optimizer.optimize(self.sim_engine, current_state, prediction_res, candidates)
            rec_dict = optimizer_decision.dict() if hasattr(optimizer_decision, "dict") else optimizer_decision.model_dump()
        except Exception as e:
            optimizer_decision = None
            rec_dict = {"status": "optimizer_failed", "error": str(e)}

        # 2. Safety Policy Evaluation
        pol_dict = {"status": "skipped"}
        if optimizer_decision and optimizer_decision.recommended_candidate:
            best_candidate = optimizer_decision.recommended_candidate
            
            # evaluate expects simulation result, let's use the baseline from optimizer
            from security.engine.what_if_simulation import WhatIfSimulationResult, SimulationBaseline
            try:
                sim_res = WhatIfSimulationResult(
                    organization_id=self.organization_id,
                    scenario_id="sc1",
                    baseline=SimulationBaseline(reachable_assets=0, critical_assets=0, attack_paths=[], path_risk_score=0.0, blast_radius=0.0, max_depth=0),
                    simulated_stage="UNKNOWN",
                    blast_radius=0.0,
                    baseline_risk_score=0.0,
                    simulated_risk_score=0.0,
                    risk_delta=0.0,
                    impact_level="LOW",
                    uncertainty="LOW",
                    state="COMPLETED",
                    predicted=current_state,
                    risk_reduction=0.0
                )
            except Exception:
                # Mock it if it fails
                sim_res = None
            
            try:
                policy_res = self.safety.evaluate(
                    prediction=prediction_res,
                    simulation=sim_res,
                    optimizer_decision=optimizer_decision,
                    candidate=best_candidate,
                    target=None
                )
                pol_dict = policy_res.dict() if hasattr(policy_res, "dict") else policy_res.model_dump()
            except Exception as e:
                pol_dict = {"decision": "DENY", "error": str(e)}
        
        out_payload = {
            "recommendation": rec_dict,
            "policy": pol_dict
        }
        
        new_event = AgentEvent(
            event_id=f"RSP-{uuid.uuid4().hex[:8]}",
            organization_id=self.organization_id,
            event_type="RESPONSE_POLICY_EVALUATED",
            occurred_at=datetime.now(timezone.utc),
            source=EventSource.RESPONSE,
            correlation_id=event.correlation_id,
            payload=out_payload,
            provenance=event.provenance + ["ResponseVerificationWorker"]
        )
        await self.emit(new_event)
        
        # Execution bounded by mode
        if self.mode == AgentMode.CONTROLLED_RESPONSE and pol_dict.get("decision") == "ALLOW":
            try:
                from security.engine.minimum_impact_response import ResponseAction
                action_name = ResponseAction.RESTRICT_IDENTITY_PRIVILEGE
                if optimizer_decision and optimizer_decision.recommended_candidate:
                    action_name = optimizer_decision.recommended_candidate.action
                    
                target = PrivilegeTarget(attachment_type="managed", policy_arn="arn")
                expected = PrivilegeExpectedState(must_be_attached=True, must_be_detached=False)
                
                # Mocking full ExecutionRequest requirements
                exec_req = ExecutionRequest(
                    organization_id=self.organization_id,
                    action=action_name,
                    target_id="auto_target",
                    privilege_target=target,
                    privilege_expected_state=expected,
                    justification="Automated response from ResponseVerificationWorker",
                    requested_by="ResponseVerificationWorker",
                    source="AUTOMATED_POLICY",
                    finding_id=event.correlation_id or "auto",
                    target={"id": "auto_target", "type": "IDENTITY"},
                    policy_decision="ALLOW",
                    policy_version="1.0",
                    policy_evaluated_at=datetime.now(timezone.utc).isoformat(),
                    approval_required=False,
                    idempotency_key=str(uuid.uuid4())
                )
            except Exception:
                exec_req = None
            
            try:
                exec_res = self.orchestrator.execute(exec_req, "mock_adapter")
                exec_event = AgentEvent(
                    event_id=f"EXC-{uuid.uuid4().hex[:8]}",
                    organization_id=self.organization_id,
                    event_type="RESPONSE_VERIFICATION_COMPLETED",
                    occurred_at=datetime.now(timezone.utc),
                    source=EventSource.VERIFICATION,
                    correlation_id=event.correlation_id,
                    payload={"execution_result": exec_res.dict() if hasattr(exec_res, "dict") else exec_res.model_dump()},
                    provenance=event.provenance + ["ExecutionOrchestrator"]
                )
                await self.emit(exec_event)
            except Exception as e:
                print(f"Exception in execute: {e}")
                pass
