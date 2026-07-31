from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import asyncio

@dataclass
class DetectionResult:
    rule_id: str
    rule_name: str
    severity: str
    resource_id: str
    resource_type: str
    mitre_technique: str
    mitre_tactic: str
    description: str
    remediation_steps: List[str]
    risk_score: float
    compliance_violations: List[str]
    timestamp: datetime = datetime.utcnow()

class DetectionPipeline:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir
        self.rules = self._load_rules()
        
    def _load_rules(self) -> List[Dict[str, Any]]:
        # Mock load from directory. In production, load from yaml files
        return [
            {
                "id": "rule-s3-public",
                "name": "Block S3 Public Access",
                "severity": "high",
                "resource_type": "aws_s3_bucket",
                "mitre_technique": "T1530 - Data from Cloud Shared Storage",
                "mitre_tactic": "Collection",
                "description": "Checks if S3 bucket permissions allow public read or write access.",
                "remediation": ["Enable 'Block all public access' settings", "Apply explicit deny bucket policies"],
                "compliance": ["CIS AWS Foundations 1.20", "PCI DSS 1.3"]
            },
            {
                "id": "rule-ssh-open",
                "name": "SSH Security Ingress Limits",
                "severity": "critical",
                "resource_type": "azure_virtual_machine",
                "mitre_technique": "T1190 - Exploit Public-Facing Application",
                "mitre_tactic": "Initial Access",
                "description": "Port 22 (SSH) open to all incoming connections.",
                "remediation": ["Restrict NSG inbound port 22 access list to trusted office IPs"],
                "compliance": ["NIST SP 800-53 AC-17"]
            }
        ]
    
    def _get_applicable_rules(self, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [r for r in self.rules if r["resource_type"] == resource.get("type")]
    
    async def evaluate_resource(self, resource: Dict[str, Any]) -> List[DetectionResult]:
        """Evaluate a single resource against all applicable rules"""
        results = []
        applicable_rules = self._get_applicable_rules(resource)
        
        # Run rules evaluation asynchronously in parallel
        tasks = [self._evaluate_rule(rule, resource) for rule in applicable_rules]
        evaluation_results = await asyncio.gather(*tasks)
        
        for result in evaluation_results:
            if result:
                results.append(result)
                
        return results
    
    async def _evaluate_rule(self, rule: Dict[str, Any], resource: Dict[str, Any]) -> Optional[DetectionResult]:
        """Evaluate a single rule against a resource"""
        try:
            # Simple rule evaluation logic based on configuration keys
            is_compliant = True
            if rule["id"] == "rule-s3-public":
                is_compliant = resource.get("acl") != "public-read"
            elif rule["id"] == "rule-ssh-open":
                is_compliant = not any(
                    ingress.get("port") == "22" and ingress.get("source") == "*"
                    for ingress in resource.get("ingress_rules", [])
                )
                
            if not is_compliant:
                return DetectionResult(
                    rule_id=rule['id'],
                    rule_name=rule['name'],
                    severity=rule.get('severity', 'medium'),
                    resource_id=resource.get('id', 'unknown'),
                    resource_type=resource.get('type', 'unknown'),
                    mitre_technique=rule.get('mitre_technique', ''),
                    mitre_tactic=rule.get('mitre_tactic', ''),
                    description=rule.get('description', ''),
                    remediation_steps=rule.get('remediation', []),
                    risk_score=self._calculate_risk_score(rule, resource),
                    compliance_violations=rule.get('compliance', [])
                )
        except Exception:
            return None
        return None
    
    def _calculate_risk_score(self, rule: Dict[str, Any], resource: Dict[str, Any]) -> float:
        """Calculate risk score based on severity, exposure, and resource criticality"""
        severity_scores = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        base_score = severity_scores.get(rule.get('severity', 'medium'), 5.0)
        
        exposure_multiplier = 1.0
        if resource.get('publicly_exposed', False):
            exposure_multiplier = 1.5
        if resource.get('contains_pii', False):
            exposure_multiplier *= 1.3
            
        criticality_multiplier = resource.get('criticality_multiplier', 1.0)
        
        final_score = base_score * exposure_multiplier * criticality_multiplier
        return min(100.0, final_score * 10.0)

class AttackGraphModel:
    """Model attack paths and potential lateral movement"""
    
    def __init__(self):
        self.relationships = []
        
    def add_relationship(self, from_resource: str, to_resource: str, risk: float):
        self.relationships.append({
            'from': from_resource,
            'to': to_resource,
            'risk': risk
        })
    
    def find_critical_paths(self) -> List[Dict[str, Any]]:
        return self.relationships
    
    def calculate_exposure_score(self, resource_id: str) -> float:
        # Sum direct incoming paths risk factor
        incoming = [r for r in self.relationships if r['to'] == resource_id]
        return sum(i['risk'] for i in incoming)
