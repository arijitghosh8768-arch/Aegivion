from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
from botocore.exceptions import ClientError
from app.cloud.aws.collectors.base import BaseCollector

class S3Collector(BaseCollector):
    """S3 bucket collector with security configuration"""
    
    def __init__(self, session, region: str = None):
        super().__init__(session, region)
        self.s3_client = session.client('s3')
        self.collector_name = "s3"
        
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect all S3 buckets with security configuration"""
        try:
            buckets = []
            response = self.s3_client.list_buckets()
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket location (requires separate API call)
                    location = self.s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location.get('LocationConstraint') or 'us-east-1'
                    if bucket_region == 'EU':
                        bucket_region = 'eu-west-1'
                    
                    # Only collect buckets in the configured region
                    if self.region and bucket_region != self.region:
                        continue
                    
                    # Collect security configuration
                    normalized = await self._normalize_bucket(bucket_name, bucket_region)
                    buckets.append(normalized)
                    
                except ClientError:
                    continue
                except Exception:
                    continue
            
            return buckets
            
        except ClientError:
            return []
        except Exception:
            return []
    
    async def _normalize_bucket(self, bucket_name: str, region: str) -> Dict[str, Any]:
        """Normalize S3 bucket to Aegivion asset format"""
        config = {}
        config['encryption_enabled'] = await self._check_encryption(bucket_name)
        config['versioning_enabled'] = await self._check_versioning(bucket_name)
        config['public_access_block'] = await self._check_public_access_block(bucket_name)
        config['has_policy'] = await self._check_policy(bucket_name)
        config['logging_enabled'] = await self._check_logging(bucket_name)
        config['tags'] = await self._get_tags(bucket_name)
        config['has_public_acl'] = await self._check_public_acl(bucket_name)
        
        return {
            "asset_id": f"s3:{bucket_name}",
            "provider": "aws",
            "type": "s3",
            "region": region,
            "name": bucket_name,
            "configuration": config,
            "relationships": [
                {
                    "type": "located_in",
                    "target_id": region,
                    "target_type": "region"
                }
            ],
            "metadata": {
                "collected_at": datetime.utcnow().isoformat(),
                "collector_version": "1.0.0",
                "source_provider": "aws"
            }
        }
    
    async def _check_encryption(self, bucket_name: str) -> Optional[bool]:
        """Check if bucket has default encryption enabled"""
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            return 'ServerSideEncryptionConfiguration' in response
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return False
            return None
    
    async def _check_versioning(self, bucket_name: str) -> bool:
        """Check if bucket has versioning enabled"""
        try:
            response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            return response.get('Status') == 'Enabled'
        except ClientError:
            return False
    
    async def _check_public_access_block(self, bucket_name: str) -> Dict[str, bool]:
        """Check public access block configuration"""
        default = {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False
        }
        
        try:
            response = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = response.get('PublicAccessBlockConfiguration', {})
            return {
                "block_public_acls": config.get('BlockPublicAcls', False),
                "ignore_public_acls": config.get('IgnorePublicAcls', False),
                "block_public_policy": config.get('BlockPublicPolicy', False),
                "restrict_public_buckets": config.get('RestrictPublicBuckets', False)
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                return default
            return default
    
    async def _check_policy(self, bucket_name: str) -> bool:
        """Check if bucket has a policy attached"""
        try:
            self.s3_client.get_bucket_policy(Bucket=bucket_name)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return False
            raise
    
    async def _check_logging(self, bucket_name: str) -> bool:
        """Check if logging is enabled for bucket"""
        try:
            response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            return 'LoggingEnabled' in response
        except ClientError:
            return False
    
    async def _get_tags(self, bucket_name: str) -> Dict[str, str]:
        """Get bucket tags"""
        try:
            response = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
            return {tag['Key']: tag['Value'] for tag in response.get('TagSet', [])}
        except ClientError:
            return {}
    
    async def _check_public_acl(self, bucket_name: str) -> bool:
        """Check if bucket has public ACLs"""
        try:
            response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in response.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') in [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ]:
                    return True
            return False
        except ClientError:
            return False
