import logging
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone

from security.engine.execution_contract import ExecutionRequest, ExecutionAction
from security.engine.aws_verification_engine import VerificationResult, VerificationStatus

logger = logging.getLogger(__name__)

class SecurityChangeRecord(BaseModel):
    organization_id: str
    target_id: str
    change_type: str
    field: str
    old_value: Any
    new_value: Any
    verified_at: datetime
    execution_id: str

class ReconciliationResult(BaseModel):
    reconciled: bool
    reason: str
    changes: List[SecurityChangeRecord] = Field(default_factory=list)

class SecurityDigitalTwinAdapter:
    """
    Interface for interacting with the Security Digital Twin data store.
    Provides isolation between the reconciliation engine and the database layer.
    """
    def get_identity(self, target_id: str, organization_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError()
        
    def update_identity(self, target_id: str, organization_id: str, updates: Dict[str, Any]) -> None:
        raise NotImplementedError()

    def record_change(self, change: SecurityChangeRecord) -> None:
        raise NotImplementedError()


class TwinReconciliationEngine:
    """
    Step 5E - Digital Twin Reconciliation
    Consumes verified observations (Step 5D) and safely updates the Digital Twin
    to reflect the true environment state, generating audit change records.
    """
    def __init__(self, twin_adapter: SecurityDigitalTwinAdapter):
        self._twin = twin_adapter
        
    def reconcile(self, request: ExecutionRequest, verification: VerificationResult) -> ReconciliationResult:
        if verification.status != VerificationStatus.VERIFIED:
            return ReconciliationResult(
                reconciled=False,
                reason=f"Cannot reconcile twin: verification status is {verification.status.value}, expected VERIFIED"
            )
            
        if request.action != ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE:
            return ReconciliationResult(
                reconciled=False,
                reason="Unsupported action for twin reconciliation"
            )
            
        if not request.target or not request.target.privilege:
            return ReconciliationResult(
                reconciled=False,
                reason="Target or target privilege missing from request contract"
            )

        identity = self._twin.get_identity(request.target.target_id, request.organization_id)
        if not identity:
            return ReconciliationResult(
                reconciled=False,
                reason=f"Target identity {request.target.target_id} not found in Digital Twin for organization"
            )
            
        current_privileges = identity.get("privileges", [])
        updated_privileges = []
        removed_privilege = None
        
        privilege_target = request.target.privilege
        
        for p in current_privileges:
            if privilege_target.attachment_type == "managed":
                if p.get("policy_arn") == privilege_target.policy_arn:
                    removed_privilege = p
                    continue
            elif privilege_target.attachment_type == "inline":
                if p.get("policy_name") == privilege_target.policy_name:
                    removed_privilege = p
                    continue
            updated_privileges.append(p)
            
        if not removed_privilege:
            # Policy wasn't in the twin anyway, but we verified it's absent in AWS.
            # So the twin is already consistent with reality.
            return ReconciliationResult(
                reconciled=True,
                reason="Twin is already consistent with verified state (policy absent)"
            )
            
        # Push targeted updates back to the Twin
        self._twin.update_identity(request.target.target_id, request.organization_id, {
            "privileges": updated_privileges,
            "last_seen_at": datetime.now(timezone.utc).isoformat()
        })
        
        change = SecurityChangeRecord(
            organization_id=request.organization_id,
            target_id=request.target.target_id,
            change_type="PRIVILEGE_REMOVED",
            field="privileges",
            old_value=current_privileges,
            new_value=updated_privileges,
            verified_at=verification.verified_at,
            execution_id=request.execution_id
        )
        self._twin.record_change(change)
        
        return ReconciliationResult(
            reconciled=True,
            reason="Twin successfully reconciled with verified state",
            changes=[change]
        )
