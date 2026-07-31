import os
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ResourceType(str, Enum):
    S3_BUCKET = "s3_bucket"
    IAM_ROLE = "iam_role"
    EC2_INSTANCE = "ec2_instance"
    RDS_INSTANCE = "rds_instance"
    LAMBDA = "lambda"
    VPC = "vpc"

@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    severity: Severity
    resource_type: ResourceType
    resource_id: str
    resource_name: str
    is_compliant: bool
    message: str
    remediation: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = datetime.utcnow()

class RuleEngine:
    def __init__(self, rules_directory: Optional[str] = None):
        self.rules_directory = rules_directory
        self.rules = self.load_rules()
        self.cache = {}
        
    def load_rules(self) -> List[Dict[str, Any]]:
        # In Day 3, we define our core compliance rules statically.
        # This will load from YAML files in later milestones.
        return [
            {
                "rule_id": "rule-s3-public",
                "rule_name": "Block S3 Public Access",
                "severity": Severity.HIGH,
                "resource_type": ResourceType.S3_BUCKET,
                "eval_fn": lambda res: res.get("acl") != "public-read" and res.get("public_access_block", {}).get("block_public_acls", True)
            },
            {
                "rule_id": "rule-ssh-open",
                "rule_name": "SSH Security Ingress Limits",
                "severity": Severity.CRITICAL,
                "resource_type": ResourceType.EC2_INSTANCE,
                "eval_fn": lambda res: not any(
                    rule.get("destination_port") == "22" and rule.get("source_address_prefix") == "*"
                    for rule in res.get("nsg_rules", [])
                )
            }
        ]
        
    def evaluate(self, resources: List[Dict[str, Any]]) -> List[RuleResult]:
        findings = []
        for resource in resources:
            for rule in self.rules:
                if self._should_apply_rule(rule, resource):
                    result = self._execute_rule(rule, resource)
                    if not result.is_compliant:
                        findings.append(result)
        return findings
    
    def _should_apply_rule(self, rule: Dict[str, Any], resource: Dict[str, Any]) -> bool:
        return rule.get('resource_type') == resource.get('type')
    
    def _execute_rule(self, rule: Dict[str, Any], resource: Dict[str, Any]) -> RuleResult:
        is_compliant = rule["eval_fn"](resource)
        message = "Resource compliant" if is_compliant else f"Non-compliance detected by {rule['rule_name']}"
        remediation = "No actions required." if is_compliant else "Apply secure configuration constraints."
        
        return RuleResult(
            rule_id=rule["rule_id"],
            rule_name=rule["rule_name"],
            severity=rule["severity"],
            resource_type=rule["resource_type"],
            resource_id=resource.get("resource_id", "unknown"),
            resource_name=resource.get("name", "unnamed"),
            is_compliant=is_compliant,
            message=message,
            remediation=remediation,
            details=resource
        )
