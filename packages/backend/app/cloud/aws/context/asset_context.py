from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    UNKNOWN = "unknown"

class Criticality(str, Enum):
    MISSION_CRITICAL = "mission_critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    UNKNOWN = "unknown"

class Exposure(str, Enum):
    INTERNET_EXPOSED = "internet_exposed"
    RESTRICTED_EXTERNAL = "restricted_external"
    PRIVATE = "private"
    UNKNOWN = "unknown"

class PrivilegeLevel(str, Enum):
    ADMINISTRATIVE = "administrative"
    ELEVATED = "elevated"
    STANDARD = "standard"
    MINIMAL = "minimal"
    UNKNOWN = "unknown"

class CollectionStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    MINIMAL = "minimal"
    FAILED = "failed"

@dataclass
class SecurityContext:
    """Comprehensive asset security context"""
    asset_id: str
    
    # Environment
    environment: Environment
    environment_source: str  # aws_tag, collector, default
    
    # Criticality
    criticality: Criticality
    criticality_source: str
    
    # Exposure
    exposure: Exposure
    exposure_evidence: List[str]
    
    # Privilege (for IAM assets)
    privilege_level: Optional[PrivilegeLevel]
    privilege_evidence: List[str]
    
    # Collection confidence
    collection_status: CollectionStatus
    collection_confidence: float  # 0.0 - 1.0
    missing_context: List[str]
    
    # Metadata
    tags: Dict[str, str]
    assessed_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "environment": self.environment.value,
            "environment_source": self.environment_source,
            "criticality": self.criticality.value,
            "criticality_source": self.criticality_source,
            "exposure": {
                "level": self.exposure.value,
                "evidence": self.exposure_evidence
            },
            "privilege": {
                "level": self.privilege_level.value if self.privilege_level else PrivilegeLevel.UNKNOWN.value,
                "evidence": self.privilege_evidence
            },
            "collection": {
                "status": self.collection_status.value,
                "confidence": self.collection_confidence,
                "missing_context": self.missing_context
            },
            "tags": self.tags,
            "assessed_at": self.assessed_at
        }

class AssetContextBuilder:
    """Build security context from assets"""
    
    def __init__(self):
        self.environment_mappings = self._load_environment_mappings()
        self.criticality_mappings = self._load_criticality_mappings()
    
    def _load_environment_mappings(self) -> Dict[str, str]:
        """Load environment tag mappings"""
        return {
            'env': 'production',
            'environment': 'production',
            'stage': 'production',
            'Environment': 'production',
            'prod': 'production',
            'staging': 'staging',
            'dev': 'development',
            'development': 'development',
            'test': 'testing',
            'testing': 'testing'
        }
    
    def _load_criticality_mappings(self) -> Dict[str, str]:
        """Load criticality tag mappings"""
        return {
            'criticality': 'mission_critical',
            'critical': 'mission_critical',
            'mission_critical': 'mission_critical',
            'high': 'high',
            'medium': 'normal',
            'low': 'low',
            'normal': 'normal'
        }
    
    def build_context(self, asset: Dict, relationships: List[Dict]) -> SecurityContext:
        """Build security context for an asset"""
        
        asset_type = asset.get('type')
        config = asset.get('configuration', {})
        tags = config.get('tags', {}) or {}
        
        # Determine environment
        environment, env_source = self._determine_environment(tags)
        
        # Determine criticality
        criticality, crit_source = self._determine_criticality(tags, asset_type)
        
        # Determine exposure
        exposure, exposure_evidence = self._determine_exposure(asset, relationships)
        
        # Determine privilege (for IAM)
        privilege_level, privilege_evidence = self._determine_privilege(asset, config)
        
        # Determine collection status
        collection_status, collection_confidence, missing = self._determine_collection_status(asset)
        
        return SecurityContext(
            asset_id=asset['asset_id'],
            environment=environment,
            environment_source=env_source,
            criticality=criticality,
            criticality_source=crit_source,
            exposure=exposure,
            exposure_evidence=exposure_evidence,
            privilege_level=privilege_level,
            privilege_evidence=privilege_evidence,
            collection_status=collection_status,
            collection_confidence=collection_confidence,
            missing_context=missing,
            tags=tags,
            assessed_at=datetime.utcnow().isoformat()
        )
    
    def _determine_environment(self, tags: Dict[str, str]) -> tuple:
        """Determine environment from tags"""
        for tag_key, tag_value in tags.items():
            normalized_key = tag_key.lower()
            if normalized_key in self.environment_mappings:
                mapping_target = self.environment_mappings[normalized_key]
                if tag_value.lower() in [mapping_target, 'prod', 'production', 'staging', 'dev', 'test', 'testing']:
                    # Resolve Env enum
                    val = tag_value.lower()
                    if val in ['prod', 'production']:
                        return Environment.PRODUCTION, 'aws_tag'
                    if val in ['staging', 'stage']:
                        return Environment.STAGING, 'aws_tag'
                    if val in ['dev', 'development']:
                        return Environment.DEVELOPMENT, 'aws_tag'
                    if val in ['test', 'testing']:
                        return Environment.TESTING, 'aws_tag'
        
        return Environment.UNKNOWN, 'default'
    
    def _determine_criticality(self, tags: Dict[str, str], asset_type: str) -> tuple:
        """Determine criticality from tags"""
        for tag_key, tag_value in tags.items():
            normalized_key = tag_key.lower()
            if normalized_key in self.criticality_mappings:
                crit_value = self.criticality_mappings[normalized_key]
                if tag_value.lower() in [crit_value, 'critical', 'high', 'normal', 'medium', 'low']:
                    val = tag_value.lower()
                    if val in ['critical', 'mission_critical']:
                        return Criticality.MISSION_CRITICAL, 'aws_tag'
                    if val == 'high':
                        return Criticality.HIGH, 'aws_tag'
                    if val in ['normal', 'medium']:
                        return Criticality.NORMAL, 'aws_tag'
                    if val == 'low':
                        return Criticality.LOW, 'aws_tag'
        
        # Default criticality based on asset type
        if asset_type in ['s3_bucket', 'rds_instance', 'database']:
            return Criticality.NORMAL, 'default'
        
        return Criticality.UNKNOWN, 'default'
    
    def _determine_exposure(self, asset: Dict, relationships: List[Dict]) -> tuple:
        """Determine exposure level"""
        evidence = []
        config = asset.get('configuration', {})
        
        # Check for public IP (EC2)
        if asset.get('type') in ['ec2_instance', 'ec2']:
            public_ip = config.get('public_ip') or config.get('public_ipv4')
            if public_ip:
                evidence.append('public_ipv4_present')
            
            # Check security group relationships
            has_public_sg = False
            for rel in relationships:
                # Support dictionary relationships
                r_dict = rel if isinstance(rel, dict) else rel.to_dict()
                if r_dict.get('relationship_type') == 'protected_by':
                    target_id = r_dict.get('target_asset_id')
                    if target_id and 'sg' in target_id:
                        has_public_sg = True
                        evidence.append('public_security_group')
            
            if public_ip and has_public_sg:
                return Exposure.INTERNET_EXPOSED, evidence
            elif public_ip:
                return Exposure.RESTRICTED_EXTERNAL, evidence
        
        # Check for public S3
        if asset.get('type') in ['s3_bucket', 's3']:
            pab = config.get('public_access_block', {})
            # Check if any public access block control is disabled
            if pab and (pab.get('block_public_acls') == False or pab.get('block_public_policy') == False):
                evidence.append('public_access_block_weakened')
                return Exposure.INTERNET_EXPOSED, evidence
        
        return Exposure.PRIVATE, evidence
    
    def _determine_privilege(self, asset: Dict, config: Dict) -> tuple:
        """Determine privilege level for IAM assets"""
        evidence = []
        
        if asset.get('type') == 'iam_user':
            # Check attached policies
            policies = config.get('attached_policies', [])
            for policy in policies:
                policy_name = policy.get('name', policy.get('policy_name', ''))
                if 'AdministratorAccess' in policy_name:
                    evidence.append('administrator_access_policy')
                    return PrivilegeLevel.ADMINISTRATIVE, evidence
                elif 'PowerUser' in policy_name:
                    evidence.append('power_user_policy')
                    return PrivilegeLevel.ELEVATED, evidence
            
            # Check groups
            groups = config.get('groups', [])
            for group in groups:
                if 'admin' in group.lower():
                    evidence.append('admin_group_membership')
                    return PrivilegeLevel.ADMINISTRATIVE, evidence
        
        if asset.get('type') == 'iam_role':
            policies = config.get('attached_policies', [])
            for policy in policies:
                policy_name = policy.get('name', policy.get('policy_name', ''))
                if 'AdministratorAccess' in policy_name:
                    evidence.append('administrator_access_role')
                    return PrivilegeLevel.ADMINISTRATIVE, evidence
        
        return PrivilegeLevel.UNKNOWN, evidence
    
    def _determine_collection_status(self, asset: Dict) -> tuple:
        """Determine collection completeness"""
        metadata = asset.get('metadata', {})
        status = metadata.get('collection_status', 'complete')
        
        if status == 'complete':
            return CollectionStatus.COMPLETE, 0.95, []
        elif status == 'partial':
            return CollectionStatus.PARTIAL, 0.70, ['partial_collection']
        elif status == 'minimal':
            return CollectionStatus.MINIMAL, 0.50, ['minimal_collection']
        else:
            return CollectionStatus.PARTIAL, 0.60, ['unknown_collection_status']
