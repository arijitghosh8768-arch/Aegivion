import logging
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    import boto3
    import botocore.exceptions
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from security.engine.execution_contract import (
    CloudResponseAdapter, TargetDescriptor, ExecutionRequest, ExecutionResult,
    ExecutionState, ExecutionErrorCode, ExecutionAction
)

logger = logging.getLogger(__name__)

def parse_iam_role_arn(arn: str) -> Optional[Dict[str, str]]:
    # format: arn:aws:iam::123456789012:role/RoleName
    match = re.match(r'^arn:aws:iam::(\d{12}):role/([\w+=,.@-]+)$', arn)
    if not match:
        return None
    return {
        "account_id": match.group(1),
        "role_name": match.group(2)
    }

class AWSResponseAdapter(CloudResponseAdapter):
    def __init__(self, session_factory=None):
        """
        session_factory: Callable[[str], boto3.Session]
        A function that returns a boto3 session for a given organization_id / account_id.
        In test environments, this can yield mocked clients.
        """
        self._session_factory = session_factory
        
    def provider_name(self) -> str:
        return "AWS"
        
    def supports(self, action: ExecutionAction, target: TargetDescriptor) -> bool:
        return action == ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE and target.provider == "aws"
        
    def validate_target(self, target: TargetDescriptor) -> bool:
        if target.target_type != "identity" or not target.target_id:
            return False
            
        if target.identity_type != "role":
            return False
            
        arn_parts = parse_iam_role_arn(target.target_id)
        if not arn_parts:
            return False
            
        # Target ARN account must match declared cloud account ID
        if target.cloud_account_id and arn_parts["account_id"] != target.cloud_account_id:
            return False
            
        if not target.privilege:
            return False
            
        if target.privilege.attachment_type not in ["managed", "inline"]:
            return False
            
        if target.privilege.attachment_type == "managed":
            if not target.privilege.policy_arn or target.privilege.policy_name:
                return False
        if target.privilege.attachment_type == "inline":
            if not target.privilege.policy_name or target.privilege.policy_arn:
                return False
                
        return True

    def _normalize_error(self, error: Exception) -> ExecutionErrorCode:
        if not BOTO3_AVAILABLE:
            return ExecutionErrorCode.INTERNAL_ERROR
            
        if isinstance(error, botocore.exceptions.ClientError):
            code = error.response.get("Error", {}).get("Code", "Unknown")
            if code in ["AccessDenied", "UnauthorizedOperation"]:
                return ExecutionErrorCode.PROVIDER_ERROR # Or we could map to more specific if we had AWS_ACCESS_DENIED, but the prompt suggested we normalize to our enum or add them. The contract only has PROVIDER_ERROR for general adapter failures.
            elif code in ["NoSuchEntity", "NotFound"]:
                return ExecutionErrorCode.INVALID_TARGET
            elif code in ["Throttling", "ThrottlingException", "TooManyRequestsException"]:
                return ExecutionErrorCode.PROVIDER_ERROR
            elif code in ["InvalidParameter", "ValidationError"]:
                return ExecutionErrorCode.INVALID_REQUEST
            return ExecutionErrorCode.PROVIDER_ERROR
        elif isinstance(error, (botocore.exceptions.ReadTimeoutError, botocore.exceptions.ConnectTimeoutError)):
            return ExecutionErrorCode.EXECUTION_TIMEOUT
            
        return ExecutionErrorCode.PROVIDER_ERROR

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        started_at = datetime.now(timezone.utc)
        
        if not self.validate_target(request.target):
            return ExecutionResult(
                execution_id=request.execution_id,
                organization_id=request.organization_id,
                state=ExecutionState.EXECUTION_FAILED,
                success=False,
                action=request.action,
                target=request.target,
                adapter=self.provider_name(),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error_code=ExecutionErrorCode.INVALID_TARGET,
                error_message="Invalid target or ARN format for AWS IAM Role",
                correlation_id=request.correlation_id
            )
            
        arn_parts = parse_iam_role_arn(request.target.target_id)
        role_name = arn_parts["role_name"]
        
        provider_metadata = {
            "provider": self.provider_name(),
            "operation": request.action.value,
            "aws_account_id": arn_parts["account_id"],
            "role_name": role_name,
            "attachment_type": request.target.privilege.attachment_type
        }
        
        if request.dry_run:
            provider_metadata["simulated"] = True
            return ExecutionResult(
                execution_id=request.execution_id,
                organization_id=request.organization_id,
                state=ExecutionState.EXECUTION_SUCCEEDED,
                success=True,
                action=request.action,
                target=request.target,
                adapter=self.provider_name(),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                provider_response_metadata=provider_metadata,
                correlation_id=request.correlation_id
            )
            
        if not BOTO3_AVAILABLE or not self._session_factory:
            return ExecutionResult(
                execution_id=request.execution_id,
                organization_id=request.organization_id,
                state=ExecutionState.EXECUTION_FAILED,
                success=False,
                action=request.action,
                target=request.target,
                adapter=self.provider_name(),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error_code=ExecutionErrorCode.INTERNAL_ERROR,
                error_message="AWS SDK or Session Factory not configured",
                correlation_id=request.correlation_id
            )
            
        try:
            # Resolve credentials securely via factory
            session = self._session_factory(request.organization_id, request.target.cloud_account_id)
            client = session.client('iam')
            
            provider_request_id = None
            
            if request.target.privilege.attachment_type == "managed":
                response = client.detach_role_policy(
                    RoleName=role_name,
                    PolicyArn=request.target.privilege.policy_arn
                )
                provider_request_id = response.get("ResponseMetadata", {}).get("RequestId")
                
            elif request.target.privilege.attachment_type == "inline":
                response = client.delete_role_policy(
                    RoleName=role_name,
                    PolicyName=request.target.privilege.policy_name
                )
                provider_request_id = response.get("ResponseMetadata", {}).get("RequestId")
                
            return ExecutionResult(
                execution_id=request.execution_id,
                organization_id=request.organization_id,
                state=ExecutionState.EXECUTION_SUCCEEDED,
                success=True,
                action=request.action,
                target=request.target,
                adapter=self.provider_name(),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                provider_request_id=provider_request_id,
                provider_response_metadata=provider_metadata,
                correlation_id=request.correlation_id
            )
            
        except Exception as e:
            logger.error(f"aws_adapter_error | execution_id={request.execution_id} | error={str(e)}")
            error_code = self._normalize_error(e)
            return ExecutionResult(
                execution_id=request.execution_id,
                organization_id=request.organization_id,
                state=ExecutionState.EXECUTION_FAILED,
                success=False,
                action=request.action,
                target=request.target,
                adapter=self.provider_name(),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error_code=error_code,
                error_message=str(e),
                correlation_id=request.correlation_id
            )
