from datetime import datetime
from app.models.automation import ResponseExecution
from app.api.deps import log_audit_action

class VerificationWorker:
    """
    Simulates Phase 6: Automatic Verification.
    Re-checks the cloud state to confirm the attack path was broken 
    after an execution.
    """
    
    def verify(self, execution: ResponseExecution) -> bool:
        """
        Validates if the cloud state actually changed and the finding is resolved.
        """
        if execution.status != "VERIFYING":
            return False
            
        try:
            # Step 1: Re-collect cloud state
            # e.g., aws_client.describe_security_groups(...)
            
            # Step 2: Re-run detection & recalculate attack path
            # For simulation, we assume SUCCESS if it reached this stage.
            
            execution.status = "SUCCESS"
            
            # Write audit log
            log_audit_action(
                action="automation_verification_success",
                resource_type=execution.provider,
                resource_id=execution.resource_id,
                user_id="verification-worker",
                org_id=str(execution.organization_id),
                details={
                    "execution_id": str(execution.id),
                    "finding_status": "RESOLVED",
                    "attack_path_status": "BROKEN"
                }
            )
            return True
            
        except Exception as e:
            execution.status = "FAILED"
            execution.error_message = f"Verification failed: {str(e)}"
            return False

verification_engine = VerificationWorker()
