from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class RelationshipType(str, Enum):
    """Standardized relationship types"""
    # Network relationships
    PROTECTED_BY = "protected_by"
    LOCATED_IN = "located_in"
    BELONGS_TO = "belongs_to"
    
    # Identity relationships
    MEMBER_OF = "member_of"
    HAS_POLICY = "has_policy"
    USES_ROLE = "uses_role"
    TRUSTS = "trusts"
    
    # Storage relationships
    PERMITS_ACCESS = "permits_access"
    HAS_LOGGING_TARGET = "has_logging_target"
    
    # Cross-domain
    ASSUMES_ROLE = "assumes_role"

@dataclass
class Relationship:
    """Standardized relationship object"""
    relationship_id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    provider: str
    confidence: str  # confirmed, derived, inferred
    source: str  # aws_api, collector, derived
    metadata: Dict[str, Any] = field(default_factory=dict)
    validated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "relationship_type": self.relationship_type.value,
            "provider": self.provider,
            "confidence": self.confidence,
            "source": self.source,
            "metadata": self.metadata,
            "validated_at": self.validated_at
        }

class RelationshipEngine:
    """Build and validate cross-resource relationships"""
    
    def __init__(self):
        self.relationships: List[Relationship] = []
        self.relationship_map: Dict[str, Set[str]] = {}
        self.orphans: List[Dict] = []
    
    def build_relationships(self, assets: List[Dict]) -> List[Relationship]:
        """Build all relationships from assets"""
        relationships = []
        
        # Build EC2 relationships
        ec2_rels = self._build_ec2_relationships(assets)
        relationships.extend(ec2_rels)
        
        # Build IAM relationships
        iam_rels = self._build_iam_relationships(assets)
        relationships.extend(iam_rels)
        
        # Build network relationships
        network_rels = self._build_network_relationships(assets)
        relationships.extend(network_rels)
        
        # Build S3 relationships
        s3_rels = self._build_s3_relationships(assets)
        relationships.extend(s3_rels)
        
        # Validate all relationships
        validated = self._validate_relationships(relationships, assets)
        
        # Track orphans
        self._track_orphans(validated, assets)
        
        self.relationships = validated
        return validated
    
    def _build_ec2_relationships(self, assets: List[Dict]) -> List[Relationship]:
        """Build EC2 relationships"""
        relationships = []
        
        for asset in assets:
            if asset.get('type') != 'ec2_instance':
                continue
            
            source_id = asset['asset_id']
            config = asset.get('configuration', {})
            
            # EC2 → Security Group (protected_by)
            for sg_id in config.get('security_groups', []):
                relationships.append(Relationship(
                    relationship_id=f"rel-{source_id}-{sg_id}",
                    source_asset_id=source_id,
                    target_asset_id=f"sg:{sg_id}",
                    relationship_type=RelationshipType.PROTECTED_BY,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
            
            # EC2 → Subnet (located_in)
            subnet_id = config.get('subnet_id')
            if subnet_id:
                relationships.append(Relationship(
                    relationship_id=f"rel-{source_id}-{subnet_id}",
                    source_asset_id=source_id,
                    target_asset_id=f"subnet:{subnet_id}",
                    relationship_type=RelationshipType.LOCATED_IN,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
            
            # EC2 → IAM Role (uses_role)
            role_arn = config.get('iam_instance_profile')
            if role_arn:
                # Extract role name from ARN
                role_name = role_arn.split('/')[-1]
                relationships.append(Relationship(
                    relationship_id=f"rel-{source_id}-{role_name}",
                    source_asset_id=source_id,
                    target_asset_id=f"iam:role:{role_name}",
                    relationship_type=RelationshipType.USES_ROLE,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
        
        return relationships
    
    def _build_iam_relationships(self, assets: List[Dict]) -> List[Relationship]:
        """Build IAM relationships"""
        relationships = []
        
        # Build user → group relationships
        user_groups = self._extract_user_groups(assets)
        for user_id, groups in user_groups.items():
            for group in groups:
                relationships.append(Relationship(
                    relationship_id=f"rel-{user_id}-{group}",
                    source_asset_id=user_id,
                    target_asset_id=f"iam:group:{group}",
                    relationship_type=RelationshipType.MEMBER_OF,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
        
        # Build user → policy relationships
        user_policies = self._extract_user_policies(assets)
        for user_id, policies in user_policies.items():
            for policy_arn in policies:
                policy_name = policy_arn.split('/')[-1]
                relationships.append(Relationship(
                    relationship_id=f"rel-{user_id}-{policy_name}",
                    source_asset_id=user_id,
                    target_asset_id=f"iam:policy:{policy_name}",
                    relationship_type=RelationshipType.HAS_POLICY,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
        
        # Build role → policy relationships
        role_policies = self._extract_role_policies(assets)
        for role_id, policies in role_policies.items():
            for policy_arn in policies:
                policy_name = policy_arn.split('/')[-1]
                relationships.append(Relationship(
                    relationship_id=f"rel-{role_id}-{policy_name}",
                    source_asset_id=role_id,
                    target_asset_id=f"iam:policy:{policy_name}",
                    relationship_type=RelationshipType.HAS_POLICY,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
        
        return relationships
    
    def _build_network_relationships(self, assets: List[Dict]) -> List[Relationship]:
        """Build network relationships"""
        relationships = []
        
        # Build subnet → vpc
        subnet_vpc_map = self._extract_subnet_vpc(assets)
        for subnet_id, vpc_id in subnet_vpc_map.items():
            if vpc_id:
                relationships.append(Relationship(
                    relationship_id=f"rel-{subnet_id}-{vpc_id}",
                    source_asset_id=f"subnet:{subnet_id}",
                    target_asset_id=f"vpc:{vpc_id}",
                    relationship_type=RelationshipType.BELONGS_TO,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
        
        # Build sg → vpc
        sg_vpc_map = self._extract_sg_vpc(assets)
        for sg_id, vpc_id in sg_vpc_map.items():
            if vpc_id:
                relationships.append(Relationship(
                    relationship_id=f"rel-{sg_id}-{vpc_id}",
                    source_asset_id=f"sg:{sg_id}",
                    target_asset_id=f"vpc:{vpc_id}",
                    relationship_type=RelationshipType.BELONGS_TO,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
        
        return relationships
        
    def _build_s3_relationships(self, assets: List[Dict]) -> List[Relationship]:
        """Build S3 relationships"""
        relationships = []
        for asset in assets:
            if asset.get('type') not in ['s3', 's3_bucket']:
                continue
            
            source_id = asset['asset_id']
            config = asset.get('configuration', {})
            
            region = asset.get('region')
            if region:
                relationships.append(Relationship(
                    relationship_id=f"rel-{source_id}-{region}",
                    source_asset_id=source_id,
                    target_asset_id=f"region:{region}",
                    relationship_type=RelationshipType.LOCATED_IN,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
            
            logging_config = config.get('logging', {})
            target_bucket = logging_config.get('target_bucket')
            if target_bucket:
                relationships.append(Relationship(
                    relationship_id=f"rel-{source_id}-{target_bucket}",
                    source_asset_id=source_id,
                    target_asset_id=f"s3:{target_bucket}",
                    relationship_type=RelationshipType.HAS_LOGGING_TARGET,
                    provider='aws',
                    confidence='confirmed',
                    source='aws_api'
                ))
        return relationships
    
    def _validate_relationships(self, relationships: List[Relationship], assets: List[Dict]) -> List[Relationship]:
        """Validate relationships against existing assets"""
        asset_ids = {a['asset_id'] for a in assets}
        
        # Allow checking subnet/vpc/sg format variations
        for a in assets:
            if a.get('type') == 'security_group' and a.get('name'):
                asset_ids.add(f"sg:{a.get('name')}")
            if a.get('type') == 'subnet' and a.get('name'):
                asset_ids.add(f"subnet:{a.get('name')}")
            if a.get('type') == 'vpc' and a.get('name'):
                asset_ids.add(f"vpc:{a.get('name')}")
                
        validated = []
        for rel in relationships:
            # Check if both assets exist or are region/generic targets
            source_exists = rel.source_asset_id in asset_ids
            target_exists = rel.target_asset_id in asset_ids or rel.target_asset_id.startswith('region:') or rel.target_asset_id.startswith('iam:policy:')
            
            if source_exists and target_exists:
                validated.append(rel)
            else:
                self.orphans.append({
                    'relationship': rel,
                    'missing_source': not source_exists,
                    'missing_target': not target_exists
                })
                logger.warning(f"Orphan relationship detected: {rel.relationship_id}")
        
        return validated
    
    def _track_orphans(self, relationships: List[Relationship], assets: List[Dict]):
        """Track orphan relationships for reporting"""
        asset_ids = {a['asset_id'] for a in assets}
        orphan_count = len(self.orphans)
        if orphan_count > 0:
            logger.info(f"Found {orphan_count} orphan relationships")
    
    def get_relationships_for_asset(self, asset_id: str) -> List[Relationship]:
        """Get all relationships for an asset"""
        return [
            rel for rel in self.relationships
            if rel.source_asset_id == asset_id or rel.target_asset_id == asset_id
        ]
    
    def get_attack_paths(self, asset_id: str) -> List[List[Relationship]]:
        """Find potential attack paths from an asset"""
        return [[rel] for rel in self.get_relationships_for_asset(asset_id)]
    
    def _extract_user_groups(self, assets: List[Dict]) -> Dict[str, List[str]]:
        """Extract user → group mappings"""
        result = {}
        for asset in assets:
            if asset.get('type') == 'iam_user':
                user_id = asset['asset_id']
                groups = asset.get('configuration', {}).get('groups', [])
                result[user_id] = groups
        return result
    
    def _extract_user_policies(self, assets: List[Dict]) -> Dict[str, List[str]]:
        """Extract user → policy mappings"""
        result = {}
        for asset in assets:
            if asset.get('type') == 'iam_user':
                user_id = asset['asset_id']
                policies = asset.get('configuration', {}).get('attached_policies', [])
                result[user_id] = [p['arn'] for p in policies]
        return result
    
    def _extract_role_policies(self, assets: List[Dict]) -> Dict[str, List[str]]:
        """Extract role → policy mappings"""
        result = {}
        for asset in assets:
            if asset.get('type') == 'iam_role':
                role_id = asset['asset_id']
                policies = asset.get('configuration', {}).get('attached_policies', [])
                result[role_id] = [p['arn'] for p in policies]
        return result
    
    def _extract_subnet_vpc(self, assets: List[Dict]) -> Dict[str, str]:
        """Extract subnet → vpc mappings"""
        result = {}
        for asset in assets:
            if asset.get('type') == 'subnet':
                subnet_id = asset.get('name')
                vpc_id = asset.get('configuration', {}).get('vpc_id')
                if subnet_id and vpc_id:
                    result[subnet_id] = vpc_id
        return result
    
    def _extract_sg_vpc(self, assets: List[Dict]) -> Dict[str, str]:
        """Extract sg → vpc mappings"""
        result = {}
        for asset in assets:
            if asset.get('type') == 'security_group':
                sg_id = asset.get('name')
                vpc_id = asset.get('configuration', {}).get('vpc_id')
                if sg_id and vpc_id:
                    result[sg_id] = vpc_id
        return result
