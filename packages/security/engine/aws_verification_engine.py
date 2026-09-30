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

from security.engine.execution_contract import ExecutionRequest, ExecutionAction, ExecutionState
from security.engine.aws_response_adapter import parse_iam_role_arn

logger = logging.getLogger(__name__)

class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

class VerificationResult(BaseModel):
    status: VerificationStatus
    reason: str
    verified_at: datetime
    provider_metadata: Optional[Dict[str, Any]] = None

class AWSVerificationEngine:
    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    def verify(self, request: ExecutionRequest) -> VerificationResult:
        if request.action != ExecutionAction.RESTRICT_IDENTITY_PRIVILEGE:
            return VerificationResult(
                status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                reason="Unsupported action for AWS verification",
                verified_at=datetime.now(timezone.utc)
            )

        if not request.target or request.target.provider != "aws":
            return VerificationResult(
                status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                reason="Target provider must be aws",
                verified_at=datetime.now(timezone.utc)
            )

        arn_parts = parse_iam_role_arn(request.target.target_id)
        if not arn_parts:
            return VerificationResult(
                status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                reason="Invalid IAM Role ARN format",
                verified_at=datetime.now(timezone.utc)
            )

        if request.target.cloud_account_id and arn_parts["account_id"] != request.target.cloud_account_id:
            return VerificationResult(
                status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                reason="Target ARN account ID mismatch",
                verified_at=datetime.now(timezone.utc)
            )

        if not request.target.privilege or not request.target.expected_privilege_state:
            return VerificationResult(
                status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                reason="Missing privilege or expected_privilege_state in target",
                verified_at=datetime.now(timezone.utc)
            )

        if not BOTO3_AVAILABLE or not self._session_factory:
            return VerificationResult(
                status=VerificationStatus.PROVIDER_ERROR,
                reason="AWS SDK or session factory unavailable",
                verified_at=datetime.now(timezone.utc)
            )
            
        if request.dry_run:
            # For dry runs, we assume it verifies based on the precondition simulated success
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                reason="Dry run verification bypassed real AWS query",
                verified_at=datetime.now(timezone.utc),
                provider_metadata={"simulated": True}
            )

        try:
            session = self._session_factory(request.organization_id, request.target.cloud_account_id)
            client = session.client('iam')
            role_name = arn_parts["role_name"]

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
                return VerificationResult(
                    status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                    reason="Unknown attachment type",
                    verified_at=datetime.now(timezone.utc)
                )

            metadata["expected_attached_after_action"] = False
            metadata["actual_attached"] = is_currently_attached

            # For RESTRICT_IDENTITY_PRIVILEGE, we expect the policy to be absent
            if is_currently_attached:
                return VerificationResult(
                    status=VerificationStatus.FAILED,
                    reason="Post-action state verification failed: Policy is still attached",
                    verified_at=datetime.now(timezone.utc),
                    provider_metadata=metadata
                )

            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                reason="Post-action state verified: Policy is successfully detached",
                verified_at=datetime.now(timezone.utc),
                provider_metadata=metadata
            )

        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if code in ["NoSuchEntity", "NotFound"]:
                return VerificationResult(
                    status=VerificationStatus.DRIFT_DETECTED,
                    reason="Role no longer exists; cannot verify intended state deterministically",
                    verified_at=datetime.now(timezone.utc)
                )
            return VerificationResult(
                status=VerificationStatus.PROVIDER_ERROR,
                reason=f"AWS API Error during verification: {code}",
                verified_at=datetime.now(timezone.utc)
            )
        except Exception as e:
            return VerificationResult(
                status=VerificationStatus.PROVIDER_ERROR,
                reason=f"Internal verification error: {str(e)}",
                verified_at=datetime.now(timezone.utc)
            )
