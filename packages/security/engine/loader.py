import os
import yaml
from typing import List, Dict, Any, Tuple
from .validator import RuleValidator

class RuleLoader:
    def __init__(self):
        self.validator = RuleValidator()

    def load_rules_from_dir(self, rules_dir: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Loads all rules from a directory of YAML files recursively.
        Returns:
            Tuple[List[Dict[str, Any]], List[str]]: (valid_rules, list_of_error_messages)
        """
        self.validator.reset()
        valid_rules = []
        errors = []
        
        if not os.path.exists(rules_dir):
            return [], [f"Rules directory does not exist: {rules_dir}"]

        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            rule_dict = yaml.safe_load(f)
                            
                        if not rule_dict or not isinstance(rule_dict, dict):
                            errors.append(f"Invalid YAML in {file}: Not a dictionary")
                            continue
                            
                        is_valid, err_msg = self.validator.validate_rule_dict(rule_dict)
                        if is_valid:
                            valid_rules.append(rule_dict)
                        else:
                            errors.append(f"Validation failed in {file}: {err_msg}")
                    except Exception as e:
                        errors.append(f"Failed to read/parse {file}: {str(e)}")
                        
        return valid_rules, errors
