from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class RiskFactor:
    name: str
    weight: float
    max_score: int
    description: str

@dataclass
class RiskScore:
    score: int  # 0-100
    level: RiskLevel
    factors: List[Dict[str, Any]]
    confidence: float

class ContextualRiskEngine:
    """Contextual risk scoring engine with explainable factors"""
    
    def __init__(self):
        self.factors = self._initialize_factors()
        self.criticality_cache = {}
    
    def _initialize_factors(self) -> Dict[str, RiskFactor]:
        """Initialize risk factors"""
        return {
            "base_severity": RiskFactor(
                name="base_severity",
                weight=1.0,
                max_score=90,
                description="Base severity of the security finding"
            ),
            "internet_exposure": RiskFactor(
                name="internet_exposure",
                weight=0.3,
                max_score=15,
                description="Resource is accessible from the internet"
            ),
            "production_asset": RiskFactor(
                name="production_asset",
                weight=0.2,
                max_score=10,
                description="Asset is in a production environment"
            ),
            "privilege_escalation": RiskFactor(
                name="privilege_escalation",
                weight=0.25,
                max_score=12,
                description="Finding enables privilege escalation"
            ),
            "data_sensitivity": RiskFactor(
                name="data_sensitivity",
                weight=0.2,
                max_score=10,
                description="Resource contains sensitive data"
            ),
            "exploitability": RiskFactor(
                name="exploitability",
                weight=0.25,
                max_score=12,
                description="Finding is easily exploitable"
            ),
            "identity_risk": RiskFactor(
                name="identity_risk",
                weight=0.3,
                max_score=15,
                description="Identity-related security risk"
            )
        }
    
    def calculate_risk_score(self, finding: Dict, asset: Dict, context: Dict = None) -> RiskScore:
        """Calculate contextual risk score for a finding"""
        score = 0
        factors = []
        
        # 1. Base severity
        base_score = self._calculate_base_severity(finding.get('severity', 'medium'))
        score += base_score
        factors.append({
            "name": "base_severity",
            "value": base_score,
            "max": self.factors["base_severity"].max_score,
            "description": f"Base severity: {finding.get('severity', 'medium')}"
        })
        
        # 2. Internet exposure
        exposure_score = self._calculate_internet_exposure(asset, finding)
        if exposure_score > 0:
            score += exposure_score
            factors.append({
                "name": "internet_exposure",
                "value": exposure_score,
                "max": self.factors["internet_exposure"].max_score,
                "description": self._get_exposure_description(asset)
            })
        
        # 3. Production asset
        prod_score = self._calculate_production_asset(asset)
        if prod_score > 0:
            score += prod_score
            factors.append({
                "name": "production_asset",
                "value": prod_score,
                "max": self.factors["production_asset"].max_score,
                "description": "Asset is in production environment"
            })
        
        # 4. Privilege escalation
        privilege_score = self._calculate_privilege_escalation(finding, asset)
        if privilege_score > 0:
            score += privilege_score
            factors.append({
                "name": "privilege_escalation",
                "value": privilege_score,
                "max": self.factors["privilege_escalation"].max_score,
                "description": self._get_privilege_description(finding)
            })
        
        # 5. Data sensitivity
        data_score = self._calculate_data_sensitivity(asset)
        if data_score > 0:
            score += data_score
            factors.append({
                "name": "data_sensitivity",
                "value": data_score,
                "max": self.factors["data_sensitivity"].max_score,
                "description": "Resource may contain sensitive data"
            })
        
        # 6. Exploitability
        exploit_score = self._calculate_exploitability(finding)
        if exploit_score > 0:
            score += exploit_score
            factors.append({
                "name": "exploitability",
                "value": exploit_score,
                "max": self.factors["exploitability"].max_score,
                "description": self._get_exploitability_description(finding)
            })
        
        # 7. Identity risk
        identity_score = self._calculate_identity_risk(finding)
        if identity_score > 0:
            score += identity_score
            factors.append({
                "name": "identity_risk",
                "value": identity_score,
                "max": self.factors["identity_risk"].max_score,
                "description": self._get_identity_description(finding)
            })
        
        # Normalize to 0-100
        score = min(100, max(0, score))
        
        # Determine level
        if score >= 80:
            level = RiskLevel.CRITICAL
        elif score >= 60:
            level = RiskLevel.HIGH
        elif score >= 40:
            level = RiskLevel.MEDIUM
        elif score >= 20:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.INFO
        
        # Calculate confidence
        confidence = self._calculate_confidence(factors)
        
        return RiskScore(
            score=score,
            level=level,
            factors=factors,
            confidence=confidence
        )
    
    def _calculate_base_severity(self, severity: str) -> int:
        """Calculate base severity score"""
        severity_mapping = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 25,
            'info': 10
        }
        return severity_mapping.get(severity.lower(), 50)
    
    def _calculate_internet_exposure(self, asset: Dict, finding: Dict) -> int:
        """Calculate internet exposure factor"""
        exposure = 0
        config = asset.get('configuration', {})
        
        # EC2 with public IP
        if asset.get('type') == 'ec2':
            if config.get('public_ip'):
                exposure = 15
            elif config.get('security_groups'):
                for sg in config.get('security_groups', []):
                    # Check if string or dict
                    if isinstance(sg, dict) and sg.get('has_internet_exposure'):
                        exposure = max(exposure, 10)
        
        # S3 with public access
        elif asset.get('type') == 's3':
            public_block = config.get('public_access_block', {})
            if public_block and not public_block.get('block_public_acls', False):
                exposure = 15
        
        # Security Group
        elif asset.get('type') == 'security_group':
            if config.get('has_internet_exposure'):
                exposure = 15
        
        return min(exposure, self.factors["internet_exposure"].max_score)
    
    def _calculate_production_asset(self, asset: Dict) -> int:
        """Calculate production asset factor"""
        tags = asset.get('configuration', {}).get('tags', {})
        environment = tags.get('Environment', tags.get('environment', '')).lower() if isinstance(tags, dict) else ''
        
        if environment in ['production', 'prod', 'live']:
            return self.factors["production_asset"].max_score
        elif environment in ['staging', 'stage', 'qa']:
            return self.factors["production_asset"].max_score // 2
        
        if asset.get('type') == 'ec2':
            vpc_id = asset.get('configuration', {}).get('vpc_id', '')
            if vpc_id and not vpc_id.startswith('vpc-dev-'):
                return self.factors["production_asset"].max_score // 2
        
        return 0
    
    def _calculate_privilege_escalation(self, finding: Dict, asset: Dict) -> int:
        """Calculate privilege escalation factor"""
        mitre_technique = finding.get('mitre_technique', '')
        privilege_techniques = ['T1098', 'T1078', 'T1053', 'T1068']
        
        if mitre_technique in privilege_techniques:
            return self.factors["privilege_escalation"].max_score
        
        if asset.get('type') == 'iam_user' and asset.get('configuration', {}).get('console_access'):
            return self.factors["privilege_escalation"].max_score
        
        return 0
    
    def _calculate_data_sensitivity(self, asset: Dict) -> int:
        """Calculate data sensitivity factor"""
        tags = asset.get('configuration', {}).get('tags', {})
        data_classification = tags.get('DataClassification', tags.get('data_classification', '')).lower() if isinstance(tags, dict) else ''
        
        if data_classification in ['sensitive', 'pii', 'phsi', 'restricted']:
            return self.factors["data_sensitivity"].max_score
        elif data_classification in ['internal', 'confidential']:
            return int(self.factors["data_sensitivity"].max_score * 0.6)
        
        return 0
    
    def _calculate_exploitability(self, finding: Dict) -> int:
        """Calculate exploitability factor"""
        evidence = finding.get('evidence', {})
        
        if evidence and evidence.get('public_exposure', False):
            return self.factors["exploitability"].max_score
        
        service_map = {
            'ssh': 12,
            'rdp': 12,
            'mysql': 10,
            'postgres': 10,
            'mongodb': 10
        }
        
        for service, score in service_map.items():
            if service in finding.get('title', '').lower():
                return score
        
        return 0
    
    def _calculate_identity_risk(self, finding: Dict) -> int:
        """Calculate identity risk factor"""
        if finding.get('resource_type') == 'iam_user':
            config = finding.get('asset_configuration', {}) or finding.get('evidence', {})
            
            score = 0
            if not config.get('mfa_enabled', True):
                score += 8
            if config.get('access_key_count', 0) > 1:
                score += 4
            if config.get('console_access', False):
                score += 3
            
            return min(score, self.factors["identity_risk"].max_score)
        
        return 0
    
    def _calculate_confidence(self, factors: List[Dict]) -> float:
        """Calculate confidence score based on available factors"""
        confidence = 0.85
        factor_count = len(factors)
        if factor_count < 3:
            confidence -= (3 - factor_count) * 0.05
        return min(1.0, max(0.0, confidence))
    
    def _get_exposure_description(self, asset: Dict) -> str:
        if asset.get('type') == 'ec2':
            return "EC2 instance has public IP address"
        elif asset.get('type') == 's3':
            return "S3 bucket has public access"
        elif asset.get('type') == 'security_group':
            return "Security group allows internet access"
        return "Resource is exposed to the internet"
    
    def _get_privilege_description(self, finding: Dict) -> str:
        mitre_technique = finding.get('mitre_technique', '')
        if mitre_technique:
            return f"MITRE ATT&CK technique {mitre_technique} - Privilege escalation"
        return "Identity has excessive privileges"
    
    def _get_exploitability_description(self, finding: Dict) -> str:
        title = finding.get('title', '').lower()
        if 'ssh' in title:
            return "SSH service is exposed and may be vulnerable to brute force attacks"
        elif 'rdp' in title:
            return "RDP service is exposed and may be vulnerable to credential attacks"
        return "Finding has high exploitability potential"
    
    def _get_identity_description(self, finding: Dict) -> str:
        if finding.get('resource_type') == 'iam_user':
            config = finding.get('asset_configuration', {}) or finding.get('evidence', {})
            issues = []
            if not config.get('mfa_enabled'):
                issues.append("MFA not enabled")
            if config.get('access_key_count', 0) > 1:
                issues.append("Multiple access keys")
            return f"Identity security issues: {', '.join(issues)}"
        return "Identity security risk"
