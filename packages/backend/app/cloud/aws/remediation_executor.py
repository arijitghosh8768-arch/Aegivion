import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from botocore.exceptions import ClientError

from app.models.remediation import RemediationPlan, RemediationAction, RemediationAuditLog
from app.models.cloud_account import CloudAccountV2
from app.cloud.aws.client import get_aws_session, AWS_CLIENT_CONFIG

logger = logging.getLogger(__name__)


class RemediationExecutor:
    """
    Executes approved remediation actions against AWS resources using assumed-role sessions.
    Provides pre-state snapshots for rollbacks, idempotency guards, and detailed failure tracking.
    """

    def __init__(self, db: Session, plan_id: str, cloud_account: Optional[CloudAccountV2] = None):
        self.db = db
        self.plan_id = plan_id
        self.cloud_account = cloud_account

    def _get_aws_session_for_account(self):
        """Creates boto3 session for target cloud account with assume-role support"""
        if self.cloud_account:
            return get_aws_session(
                role_arn=self.cloud_account.role_arn,
                external_id=self.cloud_account.external_id,
                aws_region=self.cloud_account.default_region or "ap-south-1"
            )
        return get_aws_session()

    def execute_plan(self, actor_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Main execution flow:
        1. Validates plan exists and status == 'APPROVED'
        2. Acquires AWS session
        3. Captures Pre-State Snapshot
        4. Runs Idempotency Check
        5. Executes AWS mutation
        6. Updates action/plan status and audit logs
        """
        plan = self.db.query(RemediationPlan).filter_by(id=self.plan_id).first()
        if not plan:
            raise ValueError(f"Remediation plan '{self.plan_id}' not found.")

        if plan.status != "APPROVED":
            raise ValueError(
                f"Cannot execute remediation plan with status '{plan.status}'. Plan must be 'APPROVED'."
            )

        # Check Expiration
        now = datetime.now(timezone.utc)
        if plan.expires_at and now > plan.expires_at:
            plan.status = "EXPIRED"
            self.db.commit()
            raise ValueError("Remediation plan has expired. Execution aborted.")

        action = self.db.query(RemediationAction).filter_by(plan_id=plan.id).first()
        if not action:
            raise ValueError(f"No remediation action found for plan '{self.plan_id}'.")

        # Fallback resolve cloud_account if not passed
        if not self.cloud_account:
            self.cloud_account = self.db.query(CloudAccountV2).filter_by(
                organization_id=plan.organization_id
            ).first()

        aws_session = self._get_aws_session_for_account()
        if not aws_session:
            err_msg = "Failed to establish authenticated AWS session (credentials or role assumption failed)."
            action.status = "FAILED"
            action.error_message = err_msg
            self.db.commit()
            raise RuntimeError(err_msg)

        action_type = action.action_type.strip().upper()
        params = action.parameters or {}

        try:
            if action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK":
                self._execute_s3_public_access_block(aws_session, plan, action, params)
            elif action_type == "REVOKE_SECURITY_GROUP_INGRESS":
                self._execute_revoke_sg_ingress(aws_session, plan, action, params)
            else:
                raise ValueError(f"Unsupported action type for execution: '{action_type}'")

            # Finalize Plan Status
            if action.status == "NO_OP":
                plan.status = "NO_OP"
            else:
                plan.status = "EXECUTED"

            # Audit Log
            audit = RemediationAuditLog(
                organization_id=plan.organization_id,
                plan_id=plan.id,
                action="PLAN_EXECUTED",
                details={
                    "status": action.status,
                    "action_type": action_type,
                    "aws_request_id": action.aws_request_id,
                    "executed_at": datetime.now(timezone.utc).isoformat()
                }
            )
            self.db.add(audit)
            self.db.commit()

            # Automatic Post-Execution Verification (Step 6.6)
            if action.status in ["COMPLETED", "NO_OP"]:
                self.verify_remediation(aws_session, plan, action)

            return {
                "plan_id": str(plan.id),
                "plan_status": plan.status,
                "action_status": action.status,
                "aws_request_id": action.aws_request_id,
                "rollback_payload": action.rollback_payload
            }

        except ClientError as e:
            err_msg = e.response.get("Error", {}).get("Message", str(e))
            action.status = "FAILED"
            action.error_message = f"AWS ClientError: {err_msg}"
            self.db.commit()
            logger.error(f"AWS Execution failed for plan {plan.id}: {err_msg}")
            raise RuntimeError(f"AWS API call failed: {err_msg}") from e
        except Exception as e:
            action.status = "FAILED"
            action.error_message = str(e)
            self.db.commit()
            logger.error(f"Execution error for plan {plan.id}: {e}")
            raise

    def _execute_s3_public_access_block(
        self,
        session,
        plan: RemediationPlan,
        action: RemediationAction,
        params: Dict[str, Any]
    ):
        bucket_name = params.get("bucket_name")
        s3_client = session.client("s3", config=AWS_CLIENT_CONFIG)

        # 1. Capture Pre-State Snapshot
        current_config = {}
        try:
            resp = s3_client.get_public_access_block(Bucket=bucket_name)
            current_config = resp.get("PublicAccessBlockConfiguration", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "NoSuchPublicAccessBlockConfiguration":
                # No existing configuration: all public access is currently allowed
                current_config = {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                }
            else:
                raise

        action.rollback_payload = {
            "bucket_name": bucket_name,
            "PublicAccessBlockConfiguration": current_config
        }

        # 2. Idempotency Check: Are all four flags already True?
        is_already_blocked = (
            current_config.get("BlockPublicAcls") is True
            and current_config.get("IgnorePublicAcls") is True
            and current_config.get("BlockPublicPolicy") is True
            and current_config.get("RestrictPublicBuckets") is True
        )
        if is_already_blocked:
            action.status = "NO_OP"
            action.aws_request_id = "IDEMPOTENT_NO_OP"
            return

        # 3. Apply Desired Public Access Block Configuration
        desired_config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
        res = s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=desired_config
        )
        metadata = res.get("ResponseMetadata", {})
        action.aws_request_id = metadata.get("RequestId") or metadata.get("HTTPHeaders", {}).get("x-amzn-requestid", "COMPLETED")
        action.status = "COMPLETED"

    def _execute_revoke_sg_ingress(
        self,
        session,
        plan: RemediationPlan,
        action: RemediationAction,
        params: Dict[str, Any]
    ):
        group_id = params.get("group_id")
        protocol = params.get("protocol", "tcp")
        from_port = int(params.get("from_port"))
        to_port = int(params.get("to_port"))
        cidr_ip = params.get("cidr_ip", "0.0.0.0/0")

        ec2_client = session.client("ec2", config=AWS_CLIENT_CONFIG)

        # 1. Capture Pre-State Snapshot
        resp = ec2_client.describe_security_groups(GroupIds=[group_id])
        groups = resp.get("SecurityGroups", [])
        if not groups:
            raise ValueError(f"Security Group '{group_id}' not found in AWS.")

        sg = groups[0]
        ip_permissions = sg.get("IpPermissions", [])

        # 2. Idempotency Check: Does the matching unrestricted rule exist?
        matching_rule = None
        for perm in ip_permissions:
            perm_proto = perm.get("IpProtocol", "")
            if perm_proto == protocol or perm_proto == "-1":
                if perm.get("FromPort") == from_port and perm.get("ToPort") == to_port:
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == cidr_ip:
                            matching_rule = perm
                            break

        if not matching_rule:
            # Rule is already absent - safe no-op
            action.status = "NO_OP"
            action.aws_request_id = "IDEMPOTENT_NO_OP"
            action.rollback_payload = {"group_id": group_id, "IpPermissions": []}
            return

        # Save exact rule snapshot for potential rollback
        action.rollback_payload = {
            "group_id": group_id,
            "IpPermissions": [
                {
                    "IpProtocol": protocol,
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": [{"CidrIp": cidr_ip}]
                }
            ]
        }

        # 3. Revoke unrestricted rule
        res = ec2_client.revoke_security_group_ingress(
            GroupId=group_id,
            IpProtocol=protocol,
            FromPort=from_port,
            ToPort=to_port,
            CidrIp=cidr_ip
        )
        metadata = res.get("ResponseMetadata", {})
        action.aws_request_id = metadata.get("RequestId") or "COMPLETED"
        action.status = "COMPLETED"

    def verify_remediation(self, session, plan: RemediationPlan, action: RemediationAction):
        """
        Post-Execution Verification:
        Re-scans the target resource in AWS.
        If the vulnerability is gone: Finding -> 'RESOLVED', Plan -> 'VERIFIED'.
        If violation persists: Plan -> 'FAILED_VERIFICATION' and triggers automatic rollback!
        """
        from app.models.finding import Finding
        action_type = action.action_type.strip().upper()
        params = action.parameters or {}
        is_resolved = False

        try:
            if action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK":
                bucket_name = params.get("bucket_name")
                s3_client = session.client("s3", config=AWS_CLIENT_CONFIG)
                resp = s3_client.get_public_access_block(Bucket=bucket_name)
                cfg = resp.get("PublicAccessBlockConfiguration", {})
                is_resolved = (
                    cfg.get("BlockPublicAcls") is True
                    and cfg.get("IgnorePublicAcls") is True
                    and cfg.get("BlockPublicPolicy") is True
                    and cfg.get("RestrictPublicBuckets") is True
                )
            elif action_type == "REVOKE_SECURITY_GROUP_INGRESS":
                group_id = params.get("group_id")
                protocol = params.get("protocol", "tcp")
                from_port = int(params.get("from_port"))
                to_port = int(params.get("to_port"))
                cidr_ip = params.get("cidr_ip", "0.0.0.0/0")

                ec2_client = session.client("ec2", config=AWS_CLIENT_CONFIG)
                resp = ec2_client.describe_security_groups(GroupIds=[group_id])
                groups = resp.get("SecurityGroups", [])
                if groups:
                    ip_perms = groups[0].get("IpPermissions", [])
                    still_present = False
                    for perm in ip_perms:
                        if perm.get("IpProtocol") in [protocol, "-1"]:
                            if perm.get("FromPort") == from_port and perm.get("ToPort") == to_port:
                                for ipr in perm.get("IpRanges", []):
                                    if ipr.get("CidrIp") == cidr_ip:
                                        still_present = True
                                        break
                    is_resolved = not still_present

        except Exception as e:
            logger.warning(f"Verification query failed: {e}")
            is_resolved = False

        if is_resolved:
            plan.status = "VERIFIED"
            if plan.finding_id:
                finding = self.db.query(Finding).filter_by(id=plan.finding_id).first()
                if finding:
                    finding.status = "resolved"
                    finding.resolved_at = datetime.now(timezone.utc)
            audit = RemediationAuditLog(
                organization_id=plan.organization_id,
                plan_id=plan.id,
                action="PLAN_VERIFIED",
                details={"verified_at": datetime.now(timezone.utc).isoformat()}
            )
            self.db.add(audit)
            self.db.commit()
            logger.info(f"Remediation Plan {plan.id} verified successfully!")
        else:
            plan.status = "FAILED_VERIFICATION"
            audit = RemediationAuditLog(
                organization_id=plan.organization_id,
                plan_id=plan.id,
                action="PLAN_FAILED_VERIFICATION",
                details={"reason": "Resource violation persists after execution. Triggering rollback."}
            )
            self.db.add(audit)
            self.db.commit()
            logger.warning(f"Remediation Plan {plan.id} failed verification. Triggering rollback...")
            # Trigger automatic rollback!
            self.rollback_plan()

    def rollback_plan(self, actor_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Rollback Engine:
        Reads action.rollback_payload and restores previous AWS resource state.
        Updates action.status = 'ROLLED_BACK' and plan.status = 'ROLLED_BACK'.
        """
        plan = self.db.query(RemediationPlan).filter_by(id=self.plan_id).first()
        if not plan:
            raise ValueError(f"Plan '{self.plan_id}' not found.")

        action = self.db.query(RemediationAction).filter_by(plan_id=plan.id).first()
        if not action:
            raise ValueError(f"No action found for plan '{self.plan_id}'.")

        payload = action.rollback_payload or {}
        action_type = action.action_type.strip().upper()

        if not payload:
            err_msg = "Cannot rollback: No rollback_payload was captured before execution."
            logger.error(err_msg)
            raise ValueError(err_msg)

        aws_session = self._get_aws_session_for_account()
        if not aws_session:
            raise RuntimeError("Failed to establish AWS session for rollback.")

        try:
            if action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK":
                bucket_name = payload.get("bucket_name")
                cfg = payload.get("PublicAccessBlockConfiguration")
                s3_client = aws_session.client("s3", config=AWS_CLIENT_CONFIG)
                if cfg:
                    s3_client.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration=cfg
                    )
            elif action_type == "REVOKE_SECURITY_GROUP_INGRESS":
                group_id = payload.get("group_id")
                ip_perms = payload.get("IpPermissions", [])
                ec2_client = aws_session.client("ec2", config=AWS_CLIENT_CONFIG)
                if ip_perms:
                    ec2_client.authorize_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=ip_perms
                    )

            action.status = "ROLLED_BACK"
            plan.status = "ROLLED_BACK"

            audit = RemediationAuditLog(
                organization_id=plan.organization_id,
                plan_id=plan.id,
                action="PLAN_ROLLED_BACK",
                details={
                    "rolled_back_at": datetime.now(timezone.utc).isoformat(),
                    "restored_payload": payload
                }
            )
            self.db.add(audit)
            self.db.commit()

            return {
                "plan_id": str(plan.id),
                "plan_status": plan.status,
                "action_status": action.status,
                "message": "Resource successfully restored to pre-remediation state."
            }

        except Exception as e:
            logger.error(f"Rollback failed for plan {plan.id}: {e}")
            action.error_message = f"Rollback failed: {str(e)}"
            self.db.commit()
            raise RuntimeError(f"Rollback execution failed: {str(e)}") from e


