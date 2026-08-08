from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
from security.schema.rule import RuleSchema, Condition, Operator
from security.engine.operators import OperatorRegistry

logger = logging.getLogger(__name__)

class RuleExecutor:
    """Enhanced rule executor with network correlation"""
    
    def __init__(self):
        self.rules: List[RuleSchema] = []
    
    def load_rules(self, rules: List[RuleSchema]):
        self.rules = [r for r in rules if r.enabled]
    
    def execute(self, asset: Dict) -> List[Dict]:
        """Execute rules against asset with correlation"""
        findings = []
        
        for rule in self.rules:
            # Check if rule applies to this asset
            if not self._applies_to_asset(rule, asset):
                continue
            
            # Evaluate condition
            if self._evaluate_condition(rule.condition, asset):
                finding = self._generate_finding(rule, asset)
                findings.append(finding)
        
        return findings
    
    def _applies_to_asset(self, rule: RuleSchema, asset: Dict) -> bool:
        """Check if rule applies to asset type"""
        if asset.get('provider') != rule.provider:
            return False
        
        # Support multiple resource types (e.g., SG rule applied to EC2)
        if rule.resource_type == 'ec2_instance':
            # If rule is for EC2, check if asset is EC2 with SG relationship
            if asset.get('type') == 'ec2_instance':
                return self._check_ec2_sg_correlation(rule, asset)
            return False
        
        # Direct resource type match with S3 type normalization
        asset_type = asset.get('type')
        rule_type = rule.resource_type
        if (asset_type == 's3' and rule_type == 's3_bucket') or (asset_type == 's3_bucket' and rule_type == 's3'):
            return True
        return asset_type == rule_type
    
    def _check_ec2_sg_correlation(self, rule: RuleSchema, asset: Dict) -> bool:
        """Check if EC2 instance has correlated security group"""
        # Check if instance has public IP
        has_public_ip = asset.get('configuration', {}).get('has_public_ip', False)
        
        # Check security groups
        sg_ids = asset.get('configuration', {}).get('security_groups', [])
        if not sg_ids:
            return False
        
        # Rule AWS-SG-007 specifically
        if rule.id == 'AWS-SG-007':
            return has_public_ip
        
        return False
    
    def _evaluate_condition(self, condition: Condition, asset: Dict) -> bool:
        """Evaluate a condition against asset"""
        try:
            # Get field value
            field_value = self._get_nested_value(asset, condition.field)
            
            # Handle special operators
            if condition.operator == Operator.NETWORK_EXPOSURE:
                return self._evaluate_network_exposure(condition, asset)
            
            # Standard operator evaluation
            return OperatorRegistry.execute(
                condition.operator.value,
                field_value,
                condition.value
            )
            
        except Exception as e:
            logger.error(f"Condition evaluation failed: {str(e)}")
            return False
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        """Get nested value using dot notation"""
        parts = path.split('.')
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current
    
    def _evaluate_network_exposure(self, condition: Condition, asset: Dict) -> bool:
        """Evaluate network exposure condition"""
        # For security groups, check if any service matches
        if asset.get('type') == 'security_group':
            exposed_services = asset.get('configuration', {}).get('exposed_services', [])
            if isinstance(condition.value, dict):
                # Check if service matches all criteria in the condition value dict
                for service in exposed_services:
                    if all(service.get(k) == v for k, v in condition.value.items()):
                        return True
            return False
        
        # For EC2, check if it's public and has public SG
        if asset.get('type') == 'ec2_instance':
            has_public_ip = asset.get('configuration', {}).get('has_public_ip', False)
            has_public_sg = asset.get('configuration', {}).get('has_public_sg', False)
            
            if has_public_ip and has_public_sg:
                return True
        
        return False
    
    def _generate_finding(self, rule: RuleSchema, asset: Dict) -> Dict:
        """Generate finding from rule evaluation"""
        # Build evidence
        evidence = self._collect_evidence(rule, asset)
        
        # Generate finding ID (5 digits for FindingSchema format)
        import time
        finding_id = f"F-{int(time.time() * 1000) % 100000:05d}"
        
        return {
            "finding_id": finding_id,
            "rule_id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "provider": rule.provider,
            "service": rule.service,
            "asset_id": asset.get('asset_id'),
            "asset_name": asset.get('name'),
            "severity": rule.severity,
            "evidence": evidence,
            "status": "open",
            "mitre_techniques": rule.mitre_techniques or [],
            "remediation_summary": rule.remediation.summary if rule.remediation else None,
            "first_seen": datetime.utcnow().isoformat() + "Z",
            "last_seen": datetime.utcnow().isoformat() + "Z",
            "tags": rule.tags or []
        }
    
    def _collect_evidence(self, rule: RuleSchema, asset: Dict) -> Dict:
        """Collect evidence for finding"""
        evidence = {
            "asset_type": asset.get('type'),
            "asset_id": asset.get('asset_id'),
            "region": asset.get('region')
        }
        
        # Add service-specific evidence
        if asset.get('type') == 'security_group':
            config = asset.get('configuration', {})
            rules = config.get('ingress_rules', [])
            
            # Find matching rules
            if rule.id == 'AWS-SG-001':  # SSH
                evidence.update({
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "sources": self._find_matching_sources(rules, 22)
                })
            elif rule.id == 'AWS-SG-004':  # All TCP
                evidence.update({
                    "protocol": "tcp",
                    "from_port": 0,
                    "to_port": 65535,
                    "sources": self._find_public_sources(rules)
                })
        
        return evidence
    
    def _find_matching_sources(self, rules: List[Dict], port: int) -> List[str]:
        """Find sources matching a specific port"""
        sources = []
        for rule in rules:
            if rule.get('from_port') == port or rule.get('to_port') == port:
                if rule.get('is_public'):
                    sources.append(rule.get('source_value') or rule.get('source'))
        return sources
    
    def _find_public_sources(self, rules: List[Dict]) -> List[str]:
        """Find all public sources in rules"""
        sources = []
        for rule in rules:
            if rule.get('is_public'):
                sources.append(rule.get('source_value') or rule.get('source'))
        return sources
