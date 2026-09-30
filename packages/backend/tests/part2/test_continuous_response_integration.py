import pytest
import asyncio
from datetime import datetime, timezone
import uuid

from security.engine.agent_controller import AgentEvent, EventSource
from security.engine.agent_workers import ResponseVerificationWorker, AgentMode

class MockAction:
    value = "Isolate"

class MockCand:
    action = MockAction()

class MockDec:
    recommended_candidate = MockCand()
    def dict(self):
        return {}

class MockPolicy:
    decision = "ALLOW"
    def dict(self):
        return {"decision": "ALLOW"}

class MockOpt:
    def generate_candidates(self, state, pred):
        return [MockCand()]
    def optimize(self, eng, state, pred, cand):
        return MockDec()

class MockSafety:
    def evaluate(self, prediction, simulation, optimizer_decision, candidate, target):
        return MockPolicy()

class MockExec:
    def dict(self):
        return {}

class MockOrch:
    def execute(self, req, adapter):
        return MockExec()

@pytest.mark.asyncio
async def test_response_verification_worker_flow():
    worker = ResponseVerificationWorker("resp-worker-1", "org1", mode=AgentMode.CONTROLLED_RESPONSE)
    worker.sim_engine = type('MockSimEngine', (), {'simulate': lambda self, scen: type('MockRes', (), {'risk_reduction': 0.0, 'dict': lambda self: {}})()})()
    worker.optimizer = MockOpt()
    worker.safety = MockSafety()
    worker.orchestrator = MockOrch()
    
    # 1. Start worker
    await worker.start()
    
    # 2. Push event
    out_events = []
    async def capture(evt):
        out_events.append(evt)
        
    worker.set_emit_callback(capture)
    
    event = AgentEvent(
        event_id=f"EVT-{uuid.uuid4().hex}",
        organization_id="org1",
        event_type="ACTIVATION_ANALYSIS_COMPLETED",
        occurred_at=datetime.now(timezone.utc),
        source=EventSource.ACTIVATION,
        correlation_id="c1",
        payload={
            "prediction": {
                "organization_id": "org1",
                "current_stage": "RESOURCE_ACCESS",
                "predictions": [],
                "uncertainty": "HIGH",
                "state": "COMPLETED"
            }
        },
        provenance=[]
    )
    
    await worker.handle_event(event)
    
    # 3. Yield to let worker process
    await asyncio.sleep(0.1)
    await worker.stop()
    
    # 4. Verify outputs
    assert len(out_events) > 0
    
    # At least RESPONSE_POLICY_EVALUATED should be there
    policy_events = [e for e in out_events if e.event_type == "RESPONSE_POLICY_EVALUATED"]
    assert len(policy_events) == 1
    
    # EXECUTION_COMPLETED should be there because policy says ALLOW
    exec_events = [e for e in out_events if e.event_type == "RESPONSE_VERIFICATION_COMPLETED"]
    assert len(exec_events) == 1
