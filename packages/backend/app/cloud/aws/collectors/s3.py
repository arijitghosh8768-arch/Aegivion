from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from botocore.exceptions import ClientError
import logging
from app.cloud.aws.collectors.base import BaseCollector, UNKNOWN

logger = logging.getLogger(__name__)

class S3Collector(BaseCollector):
    """Hardened S3 collector with comprehensive security metadata"""
    
    def __init__(self, session, region: Optional[str] = None):
        super().__init__(session, region)
        self.s3_client = session.client('s3')
        self.collector_name = "s3"
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect S3 buckets with complete security configuration"""
        try:
            buckets = []
            response = self.s3_client.list_buckets()
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Get region
                    region = await self._get_bucket_region(bucket_name)
                    
                    # Only collect buckets in configured region
                    if self.region and region != self.region:
                        continue
                    
                    # Collect security configuration with per-control error handling
                    security_config = await self._collect_security_config(bucket_name)
                    security_config['created_at'] = bucket['CreationDate'].isoformat()
                    
                    normalized = await self._normalize_bucket(bucket_name, region, security_config)
                    buckets.append(normalized)
                    
                except ClientError as e:
                    if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                        logger.warning(f"Access denied for bucket {bucket_name}")
                        # Still save with partial data
                        partial_config = await self._collect_partial_config(bucket_name)
                        if partial_config:
                            partial_config['created_at'] = bucket['CreationDate'].isoformat()
                            normalized = await self._normalize_bucket(bucket_name, region, partial_config)
                            normalized['metadata']['collection_status'] = 'partial'
                            buckets.append(normalized)
                    else:
                        logger.error(f"Failed to collect bucket {bucket_name}: {str(e)}")
                        continue
                        
            logger.info(f"Collected {len(buckets)} S3 buckets from {self.region or 'all'}")
            return buckets
            
        except ClientError as e:
            logger.error(f"S3 collection failed: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error in S3 collection: {str(e)}")
            return []
    
    async def _collect_security_config(self, bucket_name: str) -> Dict[str, Any]:
        """Collect complete security configuration with per-control handling"""
        
        config = {
            'public_access_block': await self._get_public_access_block(bucket_name),
            'encryption': await self._get_encryption_config(bucket_name),
            'versioning': await self._get_versioning_config(bucket_name),
            'logging': await self._get_logging_config(bucket_name),
            'policy': await self._get_policy_status(bucket_name),
            'acl': await self._get_acl_status(bucket_name),
            'tags': await self._get_tags(bucket_name),
            'collection_status': 'complete'
        }
        
        # Legacy mappings for backward compatibility
        config['encryption_enabled'] = config['encryption'].get('enabled')
        config['versioning_enabled'] = config['versioning'].get('enabled')
        config['logging_enabled'] = config['logging'].get('enabled')
        config['has_policy'] = config['policy'].get('exists')
        config['has_public_acl'] = config['acl'].get('has_public_grants')
        config['public_access'] = config['policy'].get('is_public') or config['acl'].get('has_public_grants')
        config['has_risky_policy'] = config['policy'].get('has_public_principal')
        
        return config
    
    async def _get_public_access_block(self, bucket_name: str) -> Dict[str, Any]:
        """Get Public Access Block configuration with unknown handling"""
        default = {
            'block_public_acls': UNKNOWN,
            'ignore_public_acls': UNKNOWN,
            'block_public_policy': UNKNOWN,
            'restrict_public_buckets': UNKNOWN
        }
        
        try:
            response = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = response.get('PublicAccessBlockConfiguration', {})
            return {
                'block_public_acls': config.get('BlockPublicAcls', False),
                'ignore_public_acls': config.get('IgnorePublicAcls', False),
                'block_public_policy': config.get('BlockPublicPolicy', False),
                'restrict_public_buckets': config.get('RestrictPublicBuckets', False)
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                # No PAB configured
                return {
                    'block_public_acls': False,
                    'ignore_public_acls': False,
                    'block_public_policy': False,
                    'restrict_public_buckets': False
                }
            if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                raise e
            logger.warning(f"Public access block check failed for {bucket_name}: {str(e)}")
            return default
    
    async def _get_encryption_config(self, bucket_name: str) -> Dict[str, Any]:
        """Get encryption configuration"""
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            encryption = response.get('ServerSideEncryptionConfiguration', {})
            rules = encryption.get('Rules', [])
            
            if rules:
                rule = rules[0]
                apply_config = rule.get('ApplyServerSideEncryptionByDefault', {})
                return {
                    'enabled': True,
                    'algorithm': apply_config.get('SSEAlgorithm', 'Unknown'),
                    'kms_key_id': apply_config.get('KMSMasterKeyID', None)
                }
            return {'enabled': False, 'algorithm': None, 'kms_key_id': None}
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return {'enabled': False, 'algorithm': None, 'kms_key_id': None}
            if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                raise e
            logger.warning(f"Encryption check failed for {bucket_name}: {str(e)}")
            return {'enabled': UNKNOWN, 'algorithm': None, 'kms_key_id': None}
    
    async def _get_versioning_config(self, bucket_name: str) -> Dict[str, Any]:
        """Get versioning configuration"""
        try:
            response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = response.get('Status', 'NotConfigured')
            return {
                'status': status,
                'enabled': status == 'Enabled',
                'mfa_delete': response.get('MFADelete', 'Disabled')
            }
        except ClientError as e:
            if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                raise e
            return {'status': 'Unknown', 'enabled': UNKNOWN, 'mfa_delete': 'Unknown'}
    
    async def _get_logging_config(self, bucket_name: str) -> Dict[str, Any]:
        """Get logging configuration"""
        try:
            response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            logging_config = response.get('LoggingEnabled', {})
            return {
                'enabled': bool(logging_config),
                'target_bucket': logging_config.get('TargetBucket', None),
                'target_prefix': logging_config.get('TargetPrefix', None)
            }
        except ClientError as e:
            if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                raise e
            return {'enabled': UNKNOWN, 'target_bucket': None, 'target_prefix': None}
    
    async def _get_policy_status(self, bucket_name: str) -> Dict[str, Any]:
        """Get policy and analyze for public access"""
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = response.get('Policy')
            
            if policy:
                # Parse and analyze policy
                import json
                policy_doc = json.loads(policy)
                is_public = self._analyze_policy_for_public_access(policy_doc)
                
                return {
                    'exists': True,
                    'is_public': is_public,
                    'has_public_principal': self._has_public_principal(policy_doc)
                }
            return {'exists': False, 'is_public': False, 'has_public_principal': False}
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return {'exists': False, 'is_public': False, 'has_public_principal': False}
            if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                raise e
            logger.warning(f"Policy check failed for {bucket_name}: {str(e)}")
            return {'exists': UNKNOWN, 'is_public': UNKNOWN, 'has_public_principal': UNKNOWN}
    
    def _analyze_policy_for_public_access(self, policy_doc: Dict) -> bool:
        """Analyze policy for public access patterns"""
        try:
            for statement in policy_doc.get('Statement', []):
                # Check for public principal
                principal = statement.get('Principal', {})
                if principal == '*' or principal.get('AWS') == '*':
                    # Check for allow effect
                    if statement.get('Effect') == 'Allow':
                        return True
            return False
        except:
            return False
    
    def _has_public_principal(self, policy_doc: Dict) -> bool:
        """Check if policy has public principal"""
        try:
            for statement in policy_doc.get('Statement', []):
                principal = statement.get('Principal', {})
                if principal == '*' or principal.get('AWS') == '*':
                    return True
            return False
        except:
            return False
    
    async def _get_acl_status(self, bucket_name: str) -> Dict[str, Any]:
        """Get ACL and check for public grants"""
        try:
            response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = response.get('Grants', [])
            
            public_grants = []
            for grant in grants:
                grantee = grant.get('Grantee', {})
                uri = grantee.get('URI', '')
                if uri in ['http://acs.amazonaws.com/groups/global/AllUsers',
                          'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']:
                    public_grants.append({
                        'grantee_type': grantee.get('Type', 'Unknown'),
                        'permission': grant.get('Permission'),
                        'uri': uri
                    })
            
            return {
                'has_public_grants': len(public_grants) > 0,
                'public_grants': public_grants,
                'grant_count': len(grants)
            }
        except ClientError as e:
            if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                raise e
            logger.warning(f"ACL check failed for {bucket_name}: {str(e)}")
            return {
                'has_public_grants': UNKNOWN,
                'public_grants': [],
                'grant_count': UNKNOWN
            }
    
    async def _get_tags(self, bucket_name: str) -> Dict[str, str]:
        """Get bucket tags"""
        try:
            response = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
            tags = response.get('TagSet', [])
            return {tag['Key']: tag['Value'] for tag in tags}
        except ClientError:
            return {}
    
    async def _get_bucket_region(self, bucket_name: str) -> str:
        """Get bucket region"""
        try:
            response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            return response.get('LocationConstraint') or 'us-east-1'
        except:
            return 'unknown'
    
    async def _normalize_bucket(self, bucket_name: str, region: str, config: Dict) -> Dict[str, Any]:
        """Normalize bucket to standard asset format"""
        return {
            "asset_id": f"s3:{bucket_name}",
            "provider": "aws",
            "type": "s3",
            "resource_type": "s3_bucket",
            "region": region,
            "name": bucket_name,
            "configuration": {
                "public_access_block": config.get('public_access_block', {}),
                "encryption": config.get('encryption', {}),
                "versioning": config.get('versioning', {}),
                "logging": config.get('logging', {}),
                "policy": config.get('policy', {}),
                "acl": config.get('acl', {}),
                "tags": config.get('tags', {}),
                "creation_date": config.get('created_at'),
                
                # Backwards compatible legacy attributes
                "encryption_enabled": config.get('encryption_enabled'),
                "versioning_enabled": config.get('versioning_enabled'),
                "logging_enabled": config.get('logging_enabled'),
                "has_policy": config.get('has_policy'),
                "has_public_acl": config.get('has_public_acl'),
                "public_access": config.get('public_access'),
                "has_risky_policy": config.get('has_risky_policy')
            },
            "relationships": [
                {
                    "type": "located_in",
                    "target_id": region,
                    "target_type": "region"
                }
            ],
            "metadata": {
                "collected_at": datetime.utcnow().isoformat(),
                "collection_status": config.get('collection_status', 'complete'),
                "collector_version": "2.0.0"
            }
        }
    
    async def _collect_partial_config(self, bucket_name: str) -> Dict[str, Any]:
        """Collect partial configuration when access is restricted"""
        try:
            pab = await self._get_public_access_block(bucket_name)
        except ClientError:
            pab = {
                'block_public_acls': UNKNOWN,
                'ignore_public_acls': UNKNOWN,
                'block_public_policy': UNKNOWN,
                'restrict_public_buckets': UNKNOWN
            }
        config = {
            'public_access_block': pab,
            'collection_status': 'partial'
        }
        return config
