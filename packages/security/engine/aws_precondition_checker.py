import logging
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timezone

try:
    import boto3
    import botocore.exceptions
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from security.engine.execution_contract import ExecutionRequest, ExecutionAction
from security.engine.aws_response_adapter import parse_iam_role_arn

logger = logging.getLogger(__name__)

class PreconditionStatus(str, Enum):
    PASS = "PASS"
    FAIL_DRIFT = "FAIL_DRIFT"
    FAIL_VALIDATION = "FAIL_VALIDATION"
    FAIL_PROVIDER_ERROR = "FAIL_PROVIDER_ERROR"

class PreconditionResult(BaseModel):
    status: PreconditionStatus
    reason: str
    checked_at: datetime
    provider_metadata: Optional[Dict[str, Any]] = None

class AWSPreconditionChecker:
    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    def check(self, request: ExecutionRequest) -> PreconditionResult:
        if request.action != ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE:
            return PreconditionResult(
                status=PreconditionStatus.FAIL_VALIDATION,
                reason="Unsupported action for AWS preconditions",
                checked_at=datetime.now(timezone.utc)
            )

        if not request.target or request.target.provider != "aws":
            return PreconditionResult(
                status=PreconditionStatus.FAIL_VALIDATION,
                reason="Target provider must be aws",
                checked_at=datetime.now(timezone.utc)
            )

        arn_parts = parse_iam_role_arn(request.target.target_id)
        if not arn_parts:
            return PreconditionResult(
                status=PreconditionStatus.FAIL_VALIDATION,
                reason="Invalid IAM Role ARN format",
                checked_at=datetime.now(timezone.utc)
            )

        if request.target.cloud_account_id and arn_parts["account_id"] != request.target.cloud_account_id:
            return PreconditionResult(
                status=PreconditionStatus.FAIL_VALIDATION,
                reason="Target ARN account ID mismatch",
                checked_at=datetime.now(timezone.utc)
            )

        if not request.target.privilege or not request.target.expected_privilege_state:
            return PreconditionResult(
                status=PreconditionStatus.FAIL_VALIDATION,
                reason="Missing privilege or expected_privilege_state in target",
                checked_at=datetime.now(timezone.utc)
            )

        if not BOTO3_AVAILABLE or not self._session_factory:
            return PreconditionResult(
                status=PreconditionStatus.FAIL_PROVIDER_ERROR,
                reason="AWS SDK or session factory unavailable",
                checked_at=datetime.now(timezone.utc)
            )

        try:
            session = self._session_factory(request.organization_id, request.target.cloud_account_id)
            client = session.client('iam')
            role_name = arn_parts["role_name"]

            # We use paginators since a role can have many policies attached.
            # But for simplicity in this read-only checker, we just call the list APIs.
            is_currently_attached = False
            metadata = {}

            if request.target.privilege.attachment_type == "managed":
                paginator = client.get_paginator('list_attached_role_policies')
                for page in paginator.paginate(RoleName=role_name):
                    for pol in page.get('AttachedPolicies', []):
                        if pol['PolicyArn'] == request.target.privilege.policy_arn:
                            is_currently_attached = True
                            break
                    if is_currently_attached:
                        break
                metadata["checked_policy_arn"] = request.target.privilege.policy_arn

            elif request.target.privilege.attachment_type == "inline":
                paginator = client.get_paginator('list_role_policies')
                for page in paginator.paginate(RoleName=role_name):
                    if request.target.privilege.policy_name in page.get('PolicyNames', []):
                        is_currently_attached = True
                        break
                metadata["checked_policy_name"] = request.target.privilege.policy_name
            else:
                return PreconditionResult(
                    status=PreconditionStatus.FAIL_VALIDATION,
                    reason="Unknown attachment type",
                    checked_at=datetime.now(timezone.utc)
                )

            metadata["expected_attached"] = request.target.expected_privilege_state.attached
            metadata["actual_attached"] = is_currently_attached

            if is_currently_attached != request.target.expected_privilege_state.attached:
                return PreconditionResult(
                    status=PreconditionStatus.FAIL_DRIFT,
                    reason=f"TOCTOU Drift Detected: expected attached={request.target.expected_privilege_state.attached}, actual attached={is_currently_attached}",
                    checked_at=datetime.now(timezone.utc),
                    provider_metadata=metadata
                )

            return PreconditionResult(
                status=PreconditionStatus.PASS,
                reason="Preconditions verified against live AWS state",
                checked_at=datetime.now(timezone.utc),
                provider_metadata=metadata
            )

        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if code in ["NoSuchEntity", "NotFound"]:
                # The role no longer exists - drift
                return PreconditionResult(
                    status=PreconditionStatus.FAIL_DRIFT,
                    reason="TOCTOU Drift Detected: Role no longer exists",
                    checked_at=datetime.now(timezone.utc)
                )
            return PreconditionResult(
                status=PreconditionStatus.FAIL_PROVIDER_ERROR,
                reason=f"AWS API Error: {code}",
                checked_at=datetime.now(timezone.utc)
            )
        except Exception as e:
            return PreconditionResult(
                status=PreconditionStatus.FAIL_PROVIDER_ERROR,
                reason=f"Internal pre-condition check error: {str(e)}",
                checked_at=datetime.now(timezone.utc)
            )
