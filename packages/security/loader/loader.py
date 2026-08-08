import yaml
import glob
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from pydantic import ValidationError
from security.schema.rule import RuleSchema
from security.engine.operators import OperatorRegistry

logger = logging.getLogger(__name__)

class RuleLoader:
    """Load and validate rules from YAML files"""
    
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules: List[RuleSchema] = []
        self.rule_ids: set = set()
        self.loader_stats = {
            'total': 0,
            'loaded': 0,
            'failed': 0,
            'duplicates': 0,
            'errors': []
        }
    
    def load_all(self) -> List[RuleSchema]:
        """Load all rules from directory"""
        pattern = str(self.rules_dir / "**/*.yaml")
        rule_files = glob.glob(pattern, recursive=True)
        
        self.loader_stats['total'] = len(rule_files)
        
        for rule_file in rule_files:
            self._load_file(rule_file)
        
        logger.info(f"Rule loading complete: {self.loader_stats}")
        return self.rules
    
    def _load_file(self, file_path: str):
        """Load a single rule file"""
        try:
            with open(file_path, 'r') as f:
                content = yaml.safe_load_all(f)
                for rule_data in content:
                    if rule_data is None:
                        continue
                    self._validate_and_add(rule_data, file_path)
        except yaml.YAMLError as e:
            self.loader_stats['failed'] += 1
            error = f"YAML error in {file_path}: {str(e)}"
            self.loader_stats['errors'].append(error)
            logger.error(error)
        except Exception as e:
            self.loader_stats['failed'] += 1
            error = f"Unexpected error in {file_path}: {str(e)}"
            self.loader_stats['errors'].append(error)
            logger.error(error)
    
    def _validate_and_add(self, rule_data: Dict, file_path: str):
        """Validate rule and add to registry"""
        try:
            # Check duplicate ID
            rule_id = rule_data.get('id')
            if rule_id in self.rule_ids:
                self.loader_stats['duplicates'] += 1
                error = f"Duplicate rule ID: {rule_id} in {file_path}"
                self.loader_stats['errors'].append(error)
                logger.warning(error)
                return
            
            # Validate with Pydantic
            rule = RuleSchema(**rule_data)
            
            # Validate operator
            operator = rule.condition.operator.value
            if operator not in OperatorRegistry.get_operators():
                error = f"Unsupported operator: {operator} in {rule.id}"
                self.loader_stats['errors'].append(error)
                logger.warning(error)
                return
            
            # Add to registry
            self.rules.append(rule)
            self.rule_ids.add(rule.id)
            self.loader_stats['loaded'] += 1
            
        except ValidationError as e:
            self.loader_stats['failed'] += 1
            error = f"Validation error in {file_path}: {str(e)}"
            self.loader_stats['errors'].append(error)
            logger.error(error)
        except Exception as e:
            self.loader_stats['failed'] += 1
            error = f"Unexpected validation error in {file_path}: {str(e)}"
            self.loader_stats['errors'].append(error)
            logger.error(error)
    
    def get_rule_by_id(self, rule_id: str) -> Optional[RuleSchema]:
        """Get rule by ID"""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def get_rules_for_provider(self, provider: str) -> List[RuleSchema]:
        """Get all rules for a provider"""
        return [r for r in self.rules if r.provider == provider]
    
    def get_rules_for_resource_type(self, resource_type: str) -> List[RuleSchema]:
        """Get all rules for a resource type"""
        return [r for r in self.rules if r.resource_type == resource_type]
    
    def get_enabled_rules(self) -> List[RuleSchema]:
        """Get all enabled rules"""
        return [r for r in self.rules if r.enabled]
