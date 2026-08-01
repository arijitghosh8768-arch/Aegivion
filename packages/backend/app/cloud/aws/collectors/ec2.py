from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
from botocore.exceptions import ClientError
from app.cloud.aws.collectors.base import BaseCollector

class EC2Collector(BaseCollector):
    """EC2 asset collector with pagination and error handling"""
    
    def __init__(self, session, region: str):
        super().__init__(session, region)
        self.ec2_client = session.client('ec2', region_name=region)
        self.collector_name = "ec2"
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect all EC2 instances with proper error handling"""
        try:
            assets = []
            paginator = self.ec2_client.get_paginator('describe_instances')
            
            # Use pagination for large accounts
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        normalized = await self._normalize_instance(instance)
                        assets.append(normalized)
            
            return assets
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                return []
            elif error_code == 'RequestLimitExceeded':
                await asyncio.sleep(2)
                return await self.collect()  # Retry once
            else:
                return []
        except Exception:
            return []
    
    async def _normalize_instance(self, instance: Dict) -> Dict[str, Any]:
        """Normalize AWS EC2 instance to Aegivion asset format"""
        
        # Extract tags
        tags = {t['Key']: t['Value'] for t in instance.get('Tags', [])}
        instance_name = tags.get('Name', instance['InstanceId'])
        
        # Extract security groups
        security_groups = [
            {
                'id': sg['GroupId'],
                'name': sg['GroupName']
            }
            for sg in instance.get('SecurityGroups', [])
        ]
        
        # Extract EBS volumes
        volumes = []
        for block_device in instance.get('BlockDeviceMappings', []):
            if 'Ebs' in block_device:
                volumes.append({
                    'volume_id': block_device['Ebs']['VolumeId'],
                    'delete_on_termination': block_device['Ebs'].get('DeleteOnTermination', False)
                })
        
        # Build normalized asset
        return {
            "asset_id": instance['InstanceId'],
            "provider": "aws",
            "type": "ec2",
            "region": self.region,
            "name": instance_name,
            "configuration": {
                "instance_type": instance.get('InstanceType'),
                "state": instance['State']['Name'],
                "architecture": instance.get('Architecture'),
                "platform": instance.get('Platform', 'linux'),
                "public_ip": instance.get('PublicIpAddress'),
                "private_ip": instance.get('PrivateIpAddress'),
                "vpc_id": instance.get('VpcId'),
                "subnet_id": instance.get('SubnetId'),
                "security_groups": [sg['id'] for sg in security_groups],
                "availability_zone": instance.get('Placement', {}).get('AvailabilityZone'),
                "launch_time": instance.get('LaunchTime', '').isoformat() if isinstance(instance.get('LaunchTime'), datetime) else str(instance.get('LaunchTime', '')),
                "iam_instance_profile": instance.get('IamInstanceProfile', {}).get('Arn'),
                "volumes": volumes,
                "tags": tags
            },
            "relationships": [
                {
                    "type": "located_in",
                    "target_id": instance.get('VpcId'),
                    "target_type": "vpc"
                },
                {
                    "type": "located_in",
                    "target_id": instance.get('SubnetId'),
                    "target_type": "subnet"
                }
            ] + [
                {
                    "type": "protected_by",
                    "target_id": sg['id'],
                    "target_type": "security_group"
                }
                for sg in security_groups
            ] + [
                {
                    "type": "attached_to",
                    "target_id": volume['volume_id'],
                    "target_type": "ebs_volume"
                }
                for volume in volumes
            ],
            "metadata": {
                "collected_at": datetime.utcnow().isoformat(),
                "collector_version": "1.0.0",
                "source_provider": "aws"
            }
        }
