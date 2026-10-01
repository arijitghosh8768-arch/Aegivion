import logging
from typing import Dict, Any

from app.aws.client import get_aws_session
from app.aws.ec2 import discover_ec2_instances
from app.aws.s3 import discover_s3_buckets
from app.aws.iam import discover_iam_users, discover_iam_roles
from app.aws.security_groups import discover_vpcs, discover_security_groups
from app.repositories.twin_persistence_repository import TwinPersistenceRepository

logger = logging.getLogger(__name__)

class AWSDiscoveryService:
    """
    Orchestrates read-only AWS asset discovery and pushes the normalized
    assets into the SecurityDigitalTwin via TwinPersistenceRepository.
    """
    
    def __init__(self, persistence_repo: TwinPersistenceRepository, organization_id: str, account_id: str):
        self.persistence_repo = persistence_repo
        self.organization_id = organization_id
        self.account_id = account_id

    def discover_all(self):
        """Run all discovery modules and store in the Digital Twin."""
        logger.info(f"Starting AWS Discovery for ORG {self.organization_id}, ACC {self.account_id}")
        session = get_aws_session()
        
        if not session:
            logger.error("Failed to acquire AWS session for discovery")
            return {"status": "error", "reason": "No AWS credentials available"}
            
        # Verify Identity / Account
        try:
            sts = session.client('sts')
            caller = sts.get_caller_identity()
            actual_account = caller.get("Account")
            if actual_account != self.account_id:
                logger.warning(f"STS Account {actual_account} does not match configured {self.account_id}. Proceeding with actual.")
                self.account_id = actual_account
        except Exception as e:
            logger.error(f"STS verification failed: {str(e)}")
            return {"status": "error", "reason": f"STS verification failed: {str(e)}"}
            
        stats = {
            "ec2_instances": 0,
            "s3_buckets": 0,
            "iam_users": 0,
            "iam_roles": 0,
            "vpcs": 0,
            "security_groups": 0
        }
        
        # 1. IAM Users
        for user in discover_iam_users(session):
            self.persistence_repo.upsert_identity(self.organization_id, {
                "native_id": user["arn"],
                "account_id": self.account_id,
                "provider": "aws",
                "identity_type": "IAM_USER",
                "status": "ACTIVE",
                "metadata_json": user
            })
            stats["iam_users"] += 1
            
        # 2. IAM Roles
        for role in discover_iam_roles(session):
            self.persistence_repo.upsert_identity(self.organization_id, {
                "native_id": role["arn"],
                "account_id": self.account_id,
                "provider": "aws",
                "identity_type": "IAM_ROLE",
                "status": "ACTIVE",
                "metadata_json": role
            })
            stats["iam_roles"] += 1

        # 3. EC2 Instances
        for ec2 in discover_ec2_instances(session):
            self.persistence_repo.upsert_asset(self.organization_id, {
                "resource_id": ec2["instance_id"],
                "account_id": self.account_id,
                "provider": "aws",
                "type": "EC2_INSTANCE",
                "region": ec2.get("region"),
                "environment": "UNKNOWN",
                "internet_exposed": ec2.get("has_public_ip", False),
                "metadata_json": ec2
            })
            stats["ec2_instances"] += 1
            
        # 4. S3 Buckets
        for s3 in discover_s3_buckets(session):
            self.persistence_repo.upsert_asset(self.organization_id, {
                "resource_id": s3["arn"],
                "account_id": self.account_id,
                "provider": "aws",
                "type": "S3_BUCKET",
                "region": s3.get("region"),
                "environment": "UNKNOWN",
                "internet_exposed": s3.get("is_public", False),
                "metadata_json": s3
            })
            stats["s3_buckets"] += 1

        # 5. VPCs
        for vpc in discover_vpcs(session):
            self.persistence_repo.upsert_asset(self.organization_id, {
                "resource_id": vpc["vpc_id"],
                "account_id": self.account_id,
                "provider": "aws",
                "type": "VPC",
                "region": vpc.get("region"),
                "environment": "UNKNOWN",
                "internet_exposed": False,
                "metadata_json": vpc
            })
            stats["vpcs"] += 1

        # 6. Security Groups
        for sg in discover_security_groups(session):
            self.persistence_repo.upsert_asset(self.organization_id, {
                "resource_id": sg["group_id"],
                "account_id": self.account_id,
                "provider": "aws",
                "type": "SECURITY_GROUP",
                "region": sg.get("region"),
                "environment": "UNKNOWN",
                "internet_exposed": False,
                "metadata_json": sg
            })
            stats["security_groups"] += 1

        logger.info(f"AWS Discovery complete. Stats: {stats}")
        return {"status": "success", "stats": stats}
