from typing import List, Dict, Any
import boto3
import logging

logger = logging.getLogger(__name__)

def discover_rds_instances(session: boto3.Session = None, region: str = "ap-south-1") -> List[Dict[str, Any]]:
    """Discover RDS instances using boto3 session and return normalized dicts"""
    if session is None:
        return []
    try:
        rds = session.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                instances.append({
                    "db_instance_id": db.get("DBInstanceIdentifier"),
                    "arn": db.get("DBInstanceArn"),
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "instance_class": db.get("DBInstanceClass"),
                    "status": db.get("DBInstanceStatus"),
                    "allocated_storage": db.get("AllocatedStorage"),
                    "storage_encrypted": db.get("StorageEncrypted", False),
                    "kms_key_id": db.get("KmsKeyId"),
                    "multi_az": db.get("MultiAZ", False),
                    "publicly_accessible": db.get("PubliclyAccessible", False),
                    "vpc_id": (db.get("DBSubnetGroup") or {}).get("VpcId"),
                    "security_groups": [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
                })
        return instances
    except Exception as e:
        logger.error(f"Failed to discover RDS instances: {e}")
        return []
