import logging
from datetime import datetime, timezone
from typing import Dict, Optional, List

from security.engine.execution_contract import (
    ExecutionRequest, ExecutionResult, ExecutionState, ExecutionEligibilityResult,
    ExecutionErrorCode, CloudResponseAdapter, ApprovalStatus, ALLOWED_ACTIONS, ExecutionSource
)
from security.engine.response_safety_policy import PolicyDecision
from security.engine.safety_controller import SafetyController, SafetyDecision

logger = logging.getLogger(__name__)

class ExecutionOrchestrator:
    def __init__(self):
        # In-memory registry for 5A idempotency
        self._idempotency_store: Dict[str, ExecutionResult] = {}
        self._active_requests: Dict[str, ExecutionRequest] = {}
        self._execution_states: Dict[str, ExecutionState] = {}
        self._adapters: List[CloudResponseAdapter] = []
        self._safety_controller = SafetyController()

    def register_adapter(self, adapter: CloudResponseAdapter):
        self._adapters.append(adapter)

    def _resolve_adapter(self, request: ExecutionRequest) -> Optional[CloudResponseAdapter]:
        for adapter in self._adapters:
            if adapter.supports(request.action, request.target):
                return adapter
        return None

    def _transition(self, request: ExecutionRequest, new_state: ExecutionState) -> bool:
        current_state = self._execution_states.get(request.execution_id)
        
        # Define allowed transitions
        allowed = {
            None: [ExecutionState.CREATED],
            ExecutionState.CREATED: [ExecutionState.VALIDATING, ExecutionState.CANCELLED],
            ExecutionState.VALIDATING: [ExecutionState.ELIGIBILITY_PENDING, ExecutionState.REJECTED, ExecutionState.CANCELLED],
            ExecutionState.ELIGIBILITY_PENDING: [ExecutionState.APPROVAL_PENDING, ExecutionState.READY, ExecutionState.CANCELLED, ExecutionState.EXPIRED, ExecutionState.REJECTED],
            ExecutionState.APPROVAL_PENDING: [ExecutionState.READY, ExecutionState.REJECTED, ExecutionState.EXPIRED, ExecutionState.CANCELLED],
            ExecutionState.READY: [ExecutionState.EXECUTING, ExecutionState.CANCELLED, ExecutionState.EXPIRED],
            ExecutionState.EXECUTING: [ExecutionState.EXECUTION_SUCCEEDED, ExecutionState.EXECUTION_FAILED, ExecutionState.CANCELLED]
        }
        
        if new_state in allowed.get(current_state, []):
            self._execution_states[request.execution_id] = new_state
            return True
        return False
        
    def _create_failed_result(self, request: ExecutionRequest, state: ExecutionState, error_code: ExecutionErrorCode, reason: str, adapter_name: str = "None") -> ExecutionResult:
        logger.warning(f"execution_rejected | execution_id={request.execution_id} | organization_id={request.organization_id} | reason={reason}")
        return ExecutionResult(
            execution_id=request.execution_id,
            organization_id=request.organization_id,
            state=state,
            success=False,
            action=request.action,
            target=request.target,
            adapter=adapter_name,
            error_code=error_code,
            error_message=reason,
            correlation_id=request.correlation_id
        )

    def cancel(self, execution_id: str) -> bool:
        current_state = self._execution_states.get(execution_id)
        if current_state in [ExecutionState.CREATED, ExecutionState.VALIDATING, ExecutionState.ELIGIBILITY_PENDING, ExecutionState.APPROVAL_PENDING, ExecutionState.READY]:
            req = self._active_requests[execution_id]
            self._transition(req, ExecutionState.CANCELLED)
            logger.info(f"execution_cancelled | execution_id={execution_id}")
            return True
        return False

    def check_eligibility(self, request: ExecutionRequest, tenant_context: str = None) -> ExecutionEligibilityResult:
        if not tenant_context:
            tenant_context = request.organization_id
            
        safety_result = self._safety_controller.evaluate(request, tenant_context)
        
        checks = {
            "tenant_valid": safety_result.decision != SafetyDecision.DENY or safety_result.error_code != ExecutionErrorCode.TENANT_MISMATCH,
            "action_allowed": safety_result.decision != SafetyDecision.EMERGENCY_STOP and request.action in ALLOWED_ACTIONS,
            "policy_valid": safety_result.decision != SafetyDecision.DENY or safety_result.error_code != ExecutionErrorCode.POLICY_DENIED,
            "policy_not_expired": safety_result.decision != SafetyDecision.DENY or safety_result.error_code != ExecutionErrorCode.POLICY_EXPIRED,
            "approval_valid": safety_result.decision != SafetyDecision.REQUIRE_APPROVAL and (safety_result.decision != SafetyDecision.DENY or safety_result.error_code not in [ExecutionErrorCode.APPROVAL_REJECTED, ExecutionErrorCode.APPROVAL_EXPIRED])
        }

        # Idempotency check against in-memory
        checks["idempotency_valid"] = True
        if request.idempotency_key in self._idempotency_store:
            existing = self._idempotency_store[request.idempotency_key]
            if existing.organization_id != request.organization_id or existing.action != request.action or existing.target.target_id != request.target.target_id:
                checks["idempotency_valid"] = False
                
        adapter = self._resolve_adapter(request)
        checks["adapter_available"] = adapter is not None
        checks["target_valid"] = adapter.validate_target(request.target) if adapter else False
        
        eligible = safety_result.decision == SafetyDecision.ALLOW and checks["action_allowed"] and checks["idempotency_valid"] and checks["adapter_available"] and checks["target_valid"]
        reason = safety_result.reason
        error_code = safety_result.error_code
        
        if safety_result.decision == SafetyDecision.ALLOW:
            if not checks["action_allowed"]:
                reason = "Action not allowed"
                error_code = ExecutionErrorCode.ACTION_NOT_ALLOWED
            elif not checks["idempotency_valid"]:
                reason = "Idempotency conflict"
                error_code = ExecutionErrorCode.IDEMPOTENCY_CONFLICT
            elif not checks["adapter_available"]:
                reason = "No adapter available"
                error_code = ExecutionErrorCode.ADAPTER_UNAVAILABLE
            elif not checks["target_valid"]:
                reason = "Invalid target for adapter"
                error_code = ExecutionErrorCode.INVALID_TARGET
            
            if not eligible and error_code is None:
                reason = "Ineligible"
                error_code = ExecutionErrorCode.INVALID_REQUEST

        return ExecutionEligibilityResult(
            eligible=eligible,
            reason=reason,
            error_code=error_code,
            checks=checks
        )

    def execute(self, request: ExecutionRequest, tenant_context: str) -> ExecutionResult:
        logger.info(f"execution_created | execution_id={request.execution_id}")
        self._transition(request, ExecutionState.CREATED)
        self._active_requests[request.execution_id] = request
        
        self._transition(request, ExecutionState.VALIDATING)
        logger.info(f"execution_validation_started | execution_id={request.execution_id}")
        
        # 1. Tenant Check
        if request.organization_id != tenant_context:
            self._transition(request, ExecutionState.REJECTED)
            return self._create_failed_result(request, ExecutionState.REJECTED, ExecutionErrorCode.TENANT_MISMATCH, "Tenant mismatch")
            
        # 2. Source Check
        if request.source not in ExecutionSource:
            self._transition(request, ExecutionState.REJECTED)
            return self._create_failed_result(request, ExecutionState.REJECTED, ExecutionErrorCode.INVALID_REQUEST, "Invalid source")
            
        # 3. Idempotency fast-path
        if request.idempotency_key in self._idempotency_store:
            existing_result = self._idempotency_store[request.idempotency_key]
            # Verify exact match
            if existing_result.organization_id != request.organization_id or existing_result.action != request.action or existing_result.target.target_id != request.target.target_id:
                self._transition(request, ExecutionState.REJECTED)
                return self._create_failed_result(request, ExecutionState.REJECTED, ExecutionErrorCode.IDEMPOTENCY_CONFLICT, "Idempotency conflict")
            
            logger.info(f"execution_replayed | execution_id={existing_result.execution_id}")
            replayed = existing_result.model_copy()
            replayed.idempotent_replay = True
            return replayed

        self._transition(request, ExecutionState.ELIGIBILITY_PENDING)
        
        eligibility = self.check_eligibility(request)
        
        if not eligibility.eligible:
            # Determine state
            if eligibility.error_code == ExecutionErrorCode.POLICY_EXPIRED:
                self._transition(request, ExecutionState.EXPIRED)
                logger.warning(f"policy_expired | execution_id={request.execution_id}")
                return self._create_failed_result(request, ExecutionState.EXPIRED, eligibility.error_code, eligibility.reason)
            
            if eligibility.error_code == ExecutionErrorCode.APPROVAL_MISSING and request.approval_status == ApprovalStatus.PENDING:
                self._transition(request, ExecutionState.APPROVAL_PENDING)
                logger.info(f"approval_pending | execution_id={request.execution_id}")
                return self._create_failed_result(request, ExecutionState.APPROVAL_PENDING, ExecutionErrorCode.APPROVAL_REQUIRED, "Approval required")
                
            self._transition(request, ExecutionState.REJECTED)
            return self._create_failed_result(request, ExecutionState.REJECTED, eligibility.error_code, eligibility.reason)
            
        # If eligible, move to READY
        self._transition(request, ExecutionState.READY)
        logger.info(f"execution_ready | execution_id={request.execution_id}")
        
        if request.dry_run:
            res = ExecutionResult(
                execution_id=request.execution_id,
                organization_id=request.organization_id,
                state=ExecutionState.EXECUTION_SUCCEEDED,
                success=True,
                action=request.action,
                target=request.target,
                adapter="DryRunAdapter",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                provider_response_metadata={"simulated": True},
                correlation_id=request.correlation_id
            )
            self._idempotency_store[request.idempotency_key] = res
            return res
            
        adapter = self._resolve_adapter(request)
        self._transition(request, ExecutionState.EXECUTING)
        logger.info(f"execution_started | execution_id={request.execution_id}")
        
        try:
            result = adapter.execute(request)
            if result.success:
                self._transition(request, ExecutionState.EXECUTION_SUCCEEDED)
                logger.info(f"execution_succeeded | execution_id={request.execution_id}")
            else:
                self._transition(request, ExecutionState.EXECUTION_FAILED)
                logger.warning(f"execution_failed | execution_id={request.execution_id}")
                
            # Update state explicitly
            result.state = self._execution_states[request.execution_id]
            self._idempotency_store[request.idempotency_key] = result
            return result
        except Exception as e:
            self._transition(request, ExecutionState.EXECUTION_FAILED)
            logger.error(f"execution_failed | execution_id={request.execution_id} | error={str(e)}")
            res = self._create_failed_result(request, ExecutionState.EXECUTION_FAILED, ExecutionErrorCode.PROVIDER_ERROR, str(e), adapter.provider_name())
            self._idempotency_store[request.idempotency_key] = res
            return res
