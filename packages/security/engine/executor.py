from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import re
from datetime import datetime

class Operator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    REGEX_MATCH = "regex_match"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"

@dataclass
class Condition:
    field: str
    operator: Operator
    value: Any
    
    def evaluate(self, data: Dict) -> bool:
        """Evaluate condition against asset data"""
        actual_value = self._get_nested_value(data, self.field)
        
        # If it is a list of resolved values, check if any value satisfies the condition
        if isinstance(actual_value, list) and not self.operator in [Operator.CONTAINS, Operator.NOT_CONTAINS]:
            return any(self._evaluate_single(val) for val in actual_value)
            
        return self._evaluate_single(actual_value)
        
    def _evaluate_single(self, actual_value: Any) -> bool:
        if actual_value is None and self.operator not in [Operator.EXISTS, Operator.NOT_EXISTS]:
            return False
        
        if self.operator == Operator.EQUALS:
            return actual_value == self.value
        elif self.operator == Operator.NOT_EQUALS:
            return actual_value != self.value
        elif self.operator == Operator.CONTAINS:
            return self.value in actual_value if isinstance(actual_value, (list, str)) else False
        elif self.operator == Operator.NOT_CONTAINS:
            return self.value not in actual_value if isinstance(actual_value, (list, str)) else True
        elif self.operator == Operator.EXISTS:
            return actual_value is not None
        elif self.operator == Operator.NOT_EXISTS:
            return actual_value is None
        elif self.operator == Operator.GREATER_THAN:
            try:
                return float(actual_value) > float(self.value)
            except Exception:
                return False
        elif self.operator == Operator.LESS_THAN:
            try:
                return float(actual_value) < float(self.value)
            except Exception:
                return False
        elif self.operator == Operator.REGEX_MATCH:
            return bool(re.match(self.value, str(actual_value))) if actual_value is not None else False
        elif self.operator == Operator.STARTS_WITH:
            return str(actual_value).startswith(str(self.value)) if actual_value is not None else False
        elif self.operator == Operator.ENDS_WITH:
            return str(actual_value).endswith(str(self.value)) if actual_value is not None else False
        
        return False
    
    def _get_nested_value(self, data: Dict, path: str):
        """Get nested value using dot notation, supporting list extraction (e.g. access_keys[*].age_days)"""
        cleaned_path = path.replace('[*]', '')
        parts = cleaned_path.split('.')
        return self._resolve_path(data, parts)

    def _resolve_path(self, current: Any, parts: List[str]) -> Any:
        if not parts:
            return current
        if current is None:
            return None
            
        part = parts[0]
        remaining = parts[1:]
        
        if isinstance(current, list):
            results = []
            for item in current:
                val = self._resolve_path(item, parts)
                if val is not None:
                    if isinstance(val, list):
                        results.extend(val)
                    else:
                        results.append(val)
            return results if results else None
            
        if isinstance(current, dict):
            val = current.get(part)
            return self._resolve_path(val, remaining)
            
        return None

@dataclass
class Rule:
    id: str
    version: int
    enabled: bool
    title: str
    provider: str
    resource_type: str
    severity: str
    description: str
    conditions: List[Condition]
    mitre_technique: Optional[str] = None
    remediation: Optional[List[str]] = None
    
    def matches_resource(self, asset: Dict) -> bool:
        """Check if rule applies to the asset"""
        return (
            asset.get('provider') == self.provider and
            asset.get('type') == self.resource_type
        )
    
    def evaluate(self, asset: Dict) -> bool:
        """Evaluate all conditions against asset"""
        if not self.enabled:
            return False
        
        if not self.matches_resource(asset):
            return False
        
        return all(condition.evaluate(asset) for condition in self.conditions)

class RuleExecutor:
    def __init__(self, rules: List[Dict]):
        self.rules = self._load_rules(rules)
    
    def _load_rules(self, rules_config: List[Dict]) -> List[Rule]:
        """Load and validate rules from config"""
        loaded_rules = []
        for config in rules_config:
            try:
                rule = Rule(
                    id=config['id'],
                    version=config.get('version', 1),
                    enabled=config.get('enabled', True),
                    title=config['title'],
                    provider=config['provider'],
                    resource_type=config['resource_type'],
                    severity=config['severity'],
                    description=config['description'],
                    conditions=[
                        Condition(
                            field=cond['field'],
                            operator=Operator(cond['operator']),
                            value=cond['value']
                        )
                        for cond in config.get('conditions', [])
                    ],
                    mitre_technique=config.get('mitre_technique'),
                    remediation=config.get('remediation', [])
                )
                loaded_rules.append(rule)
            except Exception as e:
                print(f"Failed to load rule {config.get('id', 'unknown')}: {str(e)}")
        
        return loaded_rules
    
    def execute(self, asset: Dict) -> List[Dict]:
        """Execute all rules against an asset"""
        findings = []
        
        for rule in self.rules:
            try:
                # If evaluating the rules returns True, it means violation detected!
                if rule.evaluate(asset):
                    finding = self._generate_finding(rule, asset)
                    findings.append(finding)
            except Exception as e:
                print(f"Rule {rule.id} execution failed: {str(e)}")
        
        return findings
    
    def _generate_finding(self, rule: Rule, asset: Dict) -> Dict:
        """Generate a finding from rule violation"""
        return {
            "finding_id": f"F-{datetime.utcnow().strftime('%Y%m%d')}-{hash(rule.id + asset['asset_id']) % 10000:04d}",
            "asset_id": asset['asset_id'],
            "rule_id": rule.id,
            "title": rule.title,
            "severity": rule.severity,
            "description": rule.description,
            "provider": asset['provider'],
            "resource_type": asset['type'],
            "region": asset.get('region'),
            "evidence": self._collect_evidence(asset, rule),
            "mitre_technique": rule.mitre_technique,
            "remediation": rule.remediation,
            "status": "open",
            "created_at": datetime.utcnow().isoformat()
        }
    
    def _collect_evidence(self, asset: Dict, rule: Rule) -> Dict:
        """Collect evidence for the finding"""
        evidence = {}
        
        for condition in rule.conditions:
            value = condition._get_nested_value(asset, condition.field)
            if value is not None:
                evidence[condition.field] = value
        
        return evidence
