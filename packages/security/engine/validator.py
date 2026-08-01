from typing import Dict, Any, Tuple, Set
from .models import Rule

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_PROVIDERS = {"aws", "azure", "gcp"}

class RuleValidator:
    def __init__(self):
        self.seen_ids: Set[str] = set()

    def reset(self):
        self.seen_ids.clear()

    def validate_rule_dict(self, rule_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates parsed YAML rule dictionary.
        Returns:
            Tuple[bool, str]: (isValid, errorMessage)
        """
        try:
            # 1. Structural/Pydantic validation
            rule = Rule(**rule_dict)
            
            # 2. Field constraint checks
            if not rule.id:
                return False, "Missing Rule ID"
                
            if rule.id in self.seen_ids:
                return False, f"Duplicate Rule ID: {rule.id}"
                
            if rule.severity.lower() not in ALLOWED_SEVERITIES:
                return False, f"Unknown severity: {rule.severity}"
                
            if rule.provider.lower() not in ALLOWED_PROVIDERS:
                return False, f"Unsupported provider: {rule.provider}"
                
            if not rule.resource_type:
                return False, "Missing resource type"
                
            if rule.version <= 0:
                return False, "Invalid version (must be >= 1)"
                
            self.seen_ids.add(rule.id)
            return True, ""
        except Exception as e:
            return False, f"Rule structure is invalid: {str(e)}"
