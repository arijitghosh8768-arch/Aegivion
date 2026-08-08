from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

class ConfidenceLevel(str, Enum):
    CONFIRMED = "confirmed"      # Direct relationship from AWS
    DERIVED = "derived"          # Relationship from analysis
    INFERRED = "inferred"        # Relationship from correlation
    LOW = "low"                  # Limited evidence

@dataclass
class Correlation:
    correlation_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low
    confidence: ConfidenceLevel
    asset_ids: List[str]
    finding_ids: List[str]
    relationships: List[Dict]
    evidence: List[Dict]
    impact: str
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence.value,
            "asset_ids": self.asset_ids,
            "finding_ids": self.finding_ids,
            "relationships": self.relationships,
            "evidence": self.evidence,
            "impact": self.impact,
            "recommendations": self.recommendations
        }

class CorrelationEngine:
    """Security correlation engine"""
    
    def __init__(self):
        self.correlations: List[Correlation] = []
        self.finding_lookup: Dict[str, Dict] = {}
        self.asset_lookup: Dict[str, Dict] = {}
        self.relationship_lookup: Dict[str, Dict] = {}
    
    def load_data(self, findings: List[Dict], assets: List[Dict], relationships: List[Dict]):
        """Load data for correlation"""
        self.finding_lookup = {f['finding_id']: f for f in findings}
        self.asset_lookup = {a['asset_id']: a for a in assets}
        # Supporting relationship lookup from dictionary lists or dataclass lists
        self.relationship_lookup = {}
        for r in relationships:
            if hasattr(r, 'relationship_id'):
                self.relationship_lookup[r.relationship_id] = r.to_dict()
            elif isinstance(r, dict) and 'relationship_id' in r:
                self.relationship_lookup[r['relationship_id']] = r
    
    def correlate(self) -> List[Correlation]:
        """Run all correlation rules"""
        correlations = []
        
        # Network correlations
        network_correlations = self._correlate_network_exposures()
        correlations.extend(network_correlations)
        
        # Identity correlations
        identity_correlations = self._correlate_identity_risks()
        correlations.extend(identity_correlations)
        
        # Cross-domain correlations
        cross_correlations = self._correlate_cross_domain()
        correlations.extend(cross_correlations)
        
        # S3 correlations
        s3_correlations = self._correlate_s3_risks()
        correlations.extend(s3_correlations)
        
        self.correlations = correlations
        return correlations
    
    def _correlate_network_exposures(self) -> List[Correlation]:
        """Correlate network exposures"""
        correlations = []
        
        # Find findings by type
        sg_findings = self._find_findings_by_rule(['AWS-SG-001', 'AWS-SG-002'])
        ec2_findings = self._find_findings_by_rule(['AWS-SG-007'])
        
        # Correlate public EC2 + public SG
        for ec2_finding in ec2_findings:
            ec2_id = ec2_finding['asset_id']
            # Find related SG findings
            related_sg = self._find_related_security_groups(ec2_id, sg_findings)
            
            if related_sg:
                correlations.append(Correlation(
                    correlation_id=f"CORR-NET-{len(correlations)+1:04d}",
                    title="Internet-exposed workload with administrative access",
                    description=f"EC2 instance {ec2_id} has public IP and associated security group allows unrestricted administrative access",
                    severity="critical",
                    confidence=ConfidenceLevel.CONFIRMED,
                    asset_ids=[ec2_id] + [sg['asset_id'] for sg in related_sg],
                    finding_ids=[ec2_finding['finding_id']] + [sg['finding_id'] for sg in related_sg],
                    relationships=self._get_relationships_for_assets([ec2_id] + [sg['asset_id'] for sg in related_sg]),
                    evidence=[
                        {"type": "public_ec2", "asset_id": ec2_id},
                        {"type": "public_sg", "asset_ids": [sg['asset_id'] for sg in related_sg]}
                    ],
                    impact="Internet-accessible administrative services significantly increase attack surface",
                    recommendations=[
                        "Restrict administrative access to authorized networks",
                        "Remove public IP if not required",
                        "Implement bastion host architecture"
                    ]
                ))
        
        return correlations
    
    def _correlate_identity_risks(self) -> List[Correlation]:
        """Correlate identity risks"""
        correlations = []
        
        # Find IAM findings
        privileged_no_mfa = self._find_findings_by_rule(['AWS-IAM-007'])
        
        # Correlate privileged user without MFA
        for finding in privileged_no_mfa:
            asset_name = finding.get('asset_name') or finding.get('resource_name') or finding.get('asset_id')
            correlations.append(Correlation(
                correlation_id=f"CORR-IAM-{len(correlations)+1:04d}",
                title="Privileged identity without MFA",
                description=f"IAM user {asset_name} has administrative privileges and no MFA",
                severity="critical",
                confidence=ConfidenceLevel.CONFIRMED,
                asset_ids=[finding['asset_id']],
                finding_ids=[finding['finding_id']],
                relationships=self._get_relationships_for_assets([finding['asset_id']]),
                evidence=finding.get('evidence', []),
                impact="Administrative identity with weak authentication is a prime target for credential theft",
                recommendations=[
                    "Enable MFA immediately for the affected user",
                    "Review administrative access requirements",
                    "Consider implementing privileged access management"
                ]
            ))
        
        return correlations
    
    def _correlate_cross_domain(self) -> List[Correlation]:
        """Correlate cross-domain risks"""
        correlations = []
        
        # Find public EC2 with privileged role
        ec2_findings = self._find_findings_by_rule(['AWS-SG-007'])
        
        for ec2_finding in ec2_findings:
            ec2_id = ec2_finding['asset_id']
            
            # Check if EC2 has IAM role
            ec2_asset = self.asset_lookup.get(ec2_id)
            if not ec2_asset:
                continue
            
            role = ec2_asset.get('configuration', {}).get('iam_instance_profile')
            if not role:
                continue
            
            # Check if role has admin permissions
            role_assets = self._find_assets_by_type('iam_role')
            for role_asset in role_assets:
                if role in role_asset.get('name', ''):
                    # Check if role has admin policy
                    if role_asset.get('configuration', {}).get('is_admin_policy', False) or role_asset.get('configuration', {}).get('is_admin', False):
                        correlations.append(Correlation(
                            correlation_id=f"CORR-X-{len(correlations)+1:04d}",
                            title="Internet-exposed workload with privileged IAM role",
                            description=f"EC2 instance {ec2_id} is internet-exposed and uses an IAM role with administrative permissions",
                            severity="critical",
                            confidence=ConfidenceLevel.CONFIRMED,
                            asset_ids=[ec2_id, role_asset['asset_id']],
                            finding_ids=[ec2_finding['finding_id']],
                            relationships=self._get_relationships_for_assets([ec2_id, role_asset['asset_id']]),
                            evidence=[
                                {"type": "public_ec2", "asset_id": ec2_id},
                                {"type": "privileged_role", "asset_id": role_asset['asset_id']}
                            ],
                            impact="Internet-exposed workload with administrative access to AWS resources",
                            recommendations=[
                                "Review IAM role permissions",
                                "Implement least-privilege access",
                                "Consider using instance profiles with limited permissions"
                            ]
                        ))
        
        return correlations
    
    def _correlate_s3_risks(self) -> List[Correlation]:
        """Correlate S3 risks"""
        correlations = []
        
        # Find S3 findings
        public_buckets = self._find_findings_by_rule(['AWS-S3-001'])
        weak_pab = self._find_findings_by_rule(['AWS-S3-002'])
        
        # Correlate public bucket with weak PAB
        for bucket in public_buckets:
            bucket_id = bucket['asset_id']
            bucket_name = bucket.get('asset_name') or bucket.get('resource_name') or bucket_id
            
            # Find if same bucket has weak PAB
            for pab_finding in weak_pab:
                if pab_finding['asset_id'] == bucket_id:
                    correlations.append(Correlation(
                        correlation_id=f"CORR-S3-{len(correlations)+1:04d}",
                        title="S3 bucket with multiple exposure issues",
                        description=f"S3 bucket {bucket_name} has public exposure and weakened public access controls",
                        severity="critical",
                        confidence=ConfidenceLevel.CONFIRMED,
                        asset_ids=[bucket_id],
                        finding_ids=[bucket['finding_id'], pab_finding['finding_id']],
                        relationships=[],
                        evidence=[
                            {"type": "public_access", "asset_id": bucket_id},
                            {"type": "weak_pab", "asset_id": bucket_id}
                        ],
                        impact="S3 bucket may be exposed to unauthorized access",
                        recommendations=[
                            "Enable all Block Public Access settings",
                            "Review bucket policies and ACLs",
                            "Consider using bucket policies with explicit denies"
                        ]
                    ))
        
        return correlations
    
    def _find_findings_by_rule(self, rule_ids: List[str]) -> List[Dict]:
        """Find findings by rule IDs"""
        findings = []
        for finding in self.finding_lookup.values():
            if finding.get('rule_id') in rule_ids:
                findings.append(finding)
        return findings
    
    def _find_assets_by_type(self, asset_type: str) -> List[Dict]:
        """Find assets by type"""
        return [a for a in self.asset_lookup.values() if a.get('type') == asset_type]
    
    def _find_related_security_groups(self, ec2_id: str, sg_findings: List[Dict]) -> List[Dict]:
        """Find security groups related to an EC2 instance"""
        # Get relationships for EC2
        relationships = self._get_relationships_for_assets([ec2_id])
        
        # Find SG relationships
        sg_assets = []
        for rel in relationships:
            if rel.get('relationship_type') == 'protected_by':
                target_id = rel.get('target_asset_id')
                if target_id:
                    for sg_finding in sg_findings:
                        if sg_finding['asset_id'] == target_id:
                            sg_assets.append(sg_finding)
        
        return sg_assets
    
    def _get_relationships_for_assets(self, asset_ids: List[str]) -> List[Dict]:
        """Get relationships for a list of assets"""
        relationships = []
        for rel in self.relationship_lookup.values():
            if rel.get('source_asset_id') in asset_ids or rel.get('target_asset_id') in asset_ids:
                relationships.append(rel)
        return relationships
