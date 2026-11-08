from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
import logging
from botocore.exceptions import ClientError
from app.cloud.aws.collectors.base import BaseCollector

logger = logging.getLogger(__name__)

class RDSCollector(BaseCollector):
    """RDS DB instance and cluster asset collector with pagination and error handling"""

    def __init__(self, session, region: str):
        super().__init__(session, region)
        self.rds_client = session.client('rds', region_name=region)
        self.collector_name = "rds"
        self.resource_type = "rds"

    async def collect(self) -> List[Dict[str, Any]]:
        """Collect all RDS instances and clusters with proper error handling"""
        try:
            assets = []
            paginator = self.rds_client.get_paginator('describe_db_instances')

            # Pagination through all RDS DB instances in region
            for page in paginator.paginate():
                for instance in page.get('DBInstances', []):
                    normalized = await self._normalize_instance(instance)
                    assets.append(normalized)

            return assets

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['UnauthorizedOperation', 'AccessDenied', 'AccessDeniedException']:
                logger.warning(f"Access denied collecting RDS in {self.region}: {e}")
                return []
            elif error_code in ['RequestLimitExceeded', 'ThrottlingException']:
                await asyncio.sleep(2)
                return await self.collect()  # Retry once
            else:
                logger.error(f"Error collecting RDS instances: {e}")
                return []
        except Exception as e:
            logger.error(f"Unexpected error in RDS collector: {e}")
            return []

    async def _normalize_instance(self, instance: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize AWS RDS instance to Aegivion standard asset schema"""
        instance_id = instance.get('DBInstanceIdentifier')
        arn = instance.get('DBInstanceArn') or f"arn:aws:rds:{self.region}:{instance_id}"

        # Extract Security Groups (VPC security groups)
        security_groups = [
            sg['VpcSecurityGroupId']
            for sg in instance.get('VpcSecurityGroups', [])
            if sg.get('Status') == 'active'
        ]

        # Extract Subnet / VPC information
        subnet_group = instance.get('DBSubnetGroup') or {}
        vpc_id = subnet_group.get('VpcId')
        subnet_ids = [sub['SubnetIdentifier'] for sub in subnet_group.get('Subnets', []) if 'SubnetIdentifier' in sub]

        # Extract Endpoint info
        endpoint = instance.get('Endpoint') or {}
        address = endpoint.get('Address')
        port = endpoint.get('Port')

        # Tags extraction
        tags = {t['Key']: t['Value'] for t in instance.get('TagList', [])} if isinstance(instance.get('TagList'), list) else {}

        # Relationships
        relationships = []
        if vpc_id:
            relationships.append({
                "type": "located_in",
                "target_id": vpc_id,
                "target_type": "vpc"
            })
        for sub_id in subnet_ids:
            relationships.append({
                "type": "located_in",
                "target_id": sub_id,
                "target_type": "subnet"
            })
        for sg_id in security_groups:
            relationships.append({
                "type": "protected_by",
                "target_id": sg_id,
                "target_type": "security_group"
            })

        return {
            "asset_id": instance_id,
            "provider": "aws",
            "type": "rds",
            "region": self.region,
            "name": instance_id,
            "configuration": {
                "arn": arn,
                "engine": instance.get('Engine'),
                "engine_version": instance.get('EngineVersion'),
                "instance_class": instance.get('DBInstanceClass'),
                "status": instance.get('DBInstanceStatus'),
                "master_username": instance.get('MasterUsername'),
                "allocated_storage": instance.get('AllocatedStorage'),
                "storage_type": instance.get('StorageType'),
                "storage_encrypted": instance.get('StorageEncrypted', False),
                "kms_key_id": instance.get('KmsKeyId'),
                "multi_az": instance.get('MultiAZ', False),
                "publicly_accessible": instance.get('PubliclyAccessible', False),
                "auto_minor_version_upgrade": instance.get('AutoMinorVersionUpgrade', False),
                "backup_retention_period": instance.get('BackupRetentionPeriod', 0),
                "endpoint_address": address,
                "endpoint_port": port,
                "vpc_id": vpc_id,
                "security_groups": security_groups,
                "deletion_protection": instance.get('DeletionProtection', False),
                "enhanced_monitoring": bool(instance.get('MonitoringInterval', 0) > 0),
                "tags": tags
            },
            "relationships": relationships,
            "metadata": {
                "collected_at": datetime.utcnow().isoformat(),
                "collector_version": "1.0.0",
                "source_provider": "aws"
            }
        }

