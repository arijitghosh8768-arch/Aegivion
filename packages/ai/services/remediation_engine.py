from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import logging
import re

logger = logging.getLogger("remediation_engine")

@dataclass
class RemediationStep:
    order: int
    action: str
    reason: str
    effort: str
    urgency: str

@dataclass
class RemediationPlan:
    finding_id: str
    priority: str
    summary: str
    steps: List[RemediationStep]
    validation: List[str]
    confidence: float
    estimated_effort: str
    references: List[str]
    
    # New fields
    immediate_action: str = ""
    console_guidance: List[str] = None
    cli_guidance: List[str] = None
    iac_guidance: List[str] = None
    is_safe: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "priority": self.priority,
            "summary": self.summary,
            "steps": [asdict(s) for s in self.steps],
            "validation": self.validation,
            "confidence": self.confidence,
            "estimated_effort": self.estimated_effort,
            "references": self.references,
            "immediate_action": self.immediate_action or self.summary,
            "console_guidance": self.console_guidance or [s.action for s in self.steps],
            "cli_guidance": self.cli_guidance or [],
            "iac_guidance": self.iac_guidance or [],
            "is_safe": self.is_safe
        }

class RemediationEngine:
    """AI remediation engine with safety boundaries"""
    
    def __init__(self, llm_provider, prompt_builder=None):
        self.llm_provider = llm_provider
        self.prompt_builder = prompt_builder
        self.safety_patterns = self._load_safety_patterns()
        self.remediation_templates = self._load_templates()
        self.fallback_plans = self._load_fallback_plans()
        
    def _load_safety_patterns(self) -> Dict[str, List[str]]:
        """Load safety patterns for CLI/IaC generation"""
        return {
            'forbidden_commands': [
                'rm -rf',
                ' rm ',
                'delete',
                'destroy',
                'drop',
                'truncate'
            ],
            'allowed_services': [
                'aws iam',
                'aws s3',
                'aws ec2',
                'terraform',
                'tofu'
            ],
            'pattern_restrictions': [
                r'\$\{.*\}',  # Shell injection risk
                r'`.*`',      # Command substitution
                r'\|.*',      # Pipe commands
            ]
        }
    
    def _load_templates(self) -> Dict[str, Any]:
        """Load remediation templates by resource type"""
        return {
            "iam_user": {
                "no_mfa": {
                    "immediate": "Enable MFA for the IAM user immediately",
                    "console": [
                        "Navigate to IAM → Users → {username}",
                        "Select 'Security credentials' tab",
                        "Click 'Assign MFA device'",
                        "Follow the MFA setup wizard"
                    ],
                    "cli": ["aws iam create-virtual-mfa-device --virtual-mfa-device-name {username}"],
                    "iac": ["resource \"aws_iam_user\" \"user\" {\n  name = \"{username}\"\n}"]
                }
            },
            "s3_bucket": {
                "public_access": {
                    "immediate": "Apply Block Public Access to the bucket",
                    "console": [
                        "Navigate to S3 → {bucket_name}",
                        "Go to Permissions tab",
                        "Click 'Edit Block Public Access'",
                        "Enable all Block Public Access settings"
                    ],
                    "cli": ["aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"],
                    "iac": ["resource \"aws_s3_bucket_public_access_block\" \"block\" {\n  bucket = \"{bucket_name}\"\n  block_public_acls = true\n}"]
                }
            }
        }

    def _load_fallback_plans(self) -> Dict[str, RemediationPlan]:
        """Load fallback plans for rule IDs"""
        return {
            "AWS-IAM-001": RemediationPlan(
                finding_id="AWS-IAM-001",
                priority="high",
                summary="Enable MFA for console-enabled IAM user",
                steps=[
                    RemediationStep(1, "Enable an MFA device for the IAM user", "Console access without MFA is a critical security risk", "5 minutes", "immediate"),
                    RemediationStep(2, "Review whether console access is still required", "Remove unnecessary interactive access", "10 minutes", "high")
                ],
                validation=["Verify MFA device is registered", "Re-run IAM assessment"],
                confidence=0.95,
                estimated_effort="15 minutes",
                references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"]
            ),
            "AWS-S3-001": RemediationPlan(
                finding_id="AWS-S3-001",
                priority="critical",
                summary="Enable S3 Public Access Block",
                steps=[
                    RemediationStep(1, "Enable S3 Block Public Access on the bucket", "Unrestricted public access block needs configuration", "5 minutes", "immediate")
                ],
                validation=["Verify block public access config is enabled"],
                confidence=0.95,
                estimated_effort="5 minutes",
                references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]
            )
        }
    
    async def generate_remediation(self, finding: Dict) -> RemediationPlan:
        """Generate safe remediation plan"""
        rule_id = finding.get('rule_id', '')
        resource_type = finding.get('resource_type', 'unknown')
        
        # Check for template
        template = self._get_template(rule_id, resource_type)
        if template:
            plan = self._apply_template(template, finding)
            return self._validate_safety(plan)
            
        # Check fallback static plan
        if rule_id in self.fallback_plans:
            plan = self.fallback_plans[rule_id]
            # Copy with correct finding_id
            plan = RemediationPlan(
                finding_id=finding.get('finding_id', 'unknown'),
                priority=plan.priority,
                summary=plan.summary,
                steps=plan.steps,
                validation=plan.validation,
                confidence=plan.confidence,
                estimated_effort=plan.estimated_effort,
                references=plan.references
            )
            return self._validate_safety(plan)
        
        # Fallback to AI generation
        try:
            prompt = self._build_remediation_prompt(finding)
            response = await self.llm_provider.generate(prompt)
            plan = self._parse_ai_response(response, finding)
            plan = self._validate_safety(plan)
            return plan
            
        except Exception as e:
            logger.error(f"Remediation generation failed: {str(e)}")
            return self._get_generic_remediation(finding)
            
    def _get_template(self, rule_id: str, resource_type: str) -> Optional[Dict]:
        template_map = {
            'AWS-IAM-001': ('iam_user', 'no_mfa'),
            'AWS-S3-001': ('s3_bucket', 'public_access'),
            'AWS-S3-002': ('s3_bucket', 'public_access'),
        }
        if rule_id in template_map:
            resource, template_key = template_map[rule_id]
            if resource in self.remediation_templates:
                return self.remediation_templates[resource].get(template_key)
        return None
        
    def _apply_template(self, template: Dict, finding: Dict) -> RemediationPlan:
        # Extract asset name from finding
        asset_name = finding.get('asset_name', finding.get('resource_name', 'RESOURCE'))
        context = {
            'username': asset_name,
            'bucket_name': asset_name
        }
        
        def substitute(text: str) -> str:
            for key, value in context.items():
                text = text.replace(f'{{{key}}}', str(value))
            return text
            
        console_guidance = [substitute(g) for g in template.get('console', [])]
        cli_guidance = [substitute(g) for g in template.get('cli', [])]
        iac_guidance = [substitute(g) for g in template.get('iac', [])]
        
        steps = []
        for i, cmd in enumerate(console_guidance):
            steps.append(RemediationStep(
                order=i+1,
                action=cmd,
                reason="Execute configuration fix step",
                effort="2 minutes",
                urgency="immediate" if i == 0 else "high"
            ))
            
        return RemediationPlan(
            finding_id=finding.get('finding_id', 'unknown'),
            priority=finding.get('severity', 'high'),
            summary=finding.get('title', 'Remediate security vulnerability'),
            steps=steps,
            validation=["Verify fix in console", "Re-run Aegivion inspection"],
            confidence=0.95,
            estimated_effort=f"{len(steps) * 2} minutes",
            references=finding.get('remediation', {}).get('references', []) if isinstance(finding.get('remediation'), dict) else [],
            immediate_action=substitute(template.get('immediate', 'Fix finding configuration')),
            console_guidance=console_guidance,
            cli_guidance=cli_guidance,
            iac_guidance=iac_guidance,
            is_safe=True
        )
    
    def _build_remediation_prompt(self, finding: Dict) -> str:
        return f"""
        Generate a remediation plan for the following security finding.
        
        FINDING:
        Title: {finding.get('title')}
        Description: {finding.get('description')}
        Severity: {finding.get('severity')}
        Rule: {finding.get('rule_id')}
        
        EVIDENCE:
        {json.dumps(finding.get('evidence', {}), indent=2)}
        
        RULES:
        1. Do NOT suggest command lines that drop, delete, or destroy data
        2. Provide clear steps and validation guidelines
        
        Response in JSON:
        {{
            "priority": "critical/high/medium/low",
            "summary": "Plan summary description",
            "immediate_action": "Single immediate action command description",
            "console_guidance": ["step 1", "step 2"],
            "cli_guidance": ["aws cli command"],
            "iac_guidance": ["terraform block"],
            "steps": [
                {{
                    "order": 1,
                    "action": "action",
                    "reason": "reason",
                    "effort": "5 minutes",
                    "urgency": "high"
                }}
            ],
            "validation": ["validation steps"],
            "confidence": 0.90,
            "estimated_effort": "total duration"
        }}
        """
    
    def _parse_ai_response(self, response: str, finding: Dict) -> RemediationPlan:
        try:
            data = json.loads(response)
            steps = [
                RemediationStep(
                    order=step.get('order', i+1),
                    action=step.get('action', ''),
                    reason=step.get('reason', ''),
                    effort=step.get('effort', 'Unknown'),
                    urgency=step.get('urgency', 'medium')
                )
                for i, step in enumerate(data.get('steps', []))
            ]
            
            return RemediationPlan(
                finding_id=finding.get('finding_id', 'unknown'),
                priority=data.get('priority', finding.get('severity', 'medium')),
                summary=data.get('summary', finding.get('title', 'Remediation needed')),
                steps=steps,
                validation=data.get('validation', []),
                confidence=float(data.get('confidence', 0.85)),
                estimated_effort=data.get('estimated_effort', '1 hour'),
                references=data.get('references', []),
                immediate_action=data.get('immediate_action', ''),
                console_guidance=data.get('console_guidance', []),
                cli_guidance=data.get('cli_guidance', []),
                iac_guidance=data.get('iac_guidance', []),
                is_safe=True
            )
        except Exception:
            return self._get_generic_remediation(finding)
            
    def _validate_safety(self, plan: RemediationPlan) -> RemediationPlan:
        """Validate CLI command safety guidelines"""
        safe_cli = []
        for cmd in (plan.cli_guidance or []):
            if self._is_safe_command(cmd):
                safe_cli.append(cmd)
            else:
                logger.warning(f"Unsafe command blocked: {cmd}")
                
        plan.cli_guidance = safe_cli
        plan.is_safe = len(safe_cli) > 0 or not plan.cli_guidance
        
        if plan.cli_guidance:
            plan.cli_guidance.append("# Review commands before execution")
            
        return plan
        
    def _is_safe_command(self, command: str) -> bool:
        command_lower = command.lower()
        for forbidden in self.safety_patterns['forbidden_commands']:
            if forbidden in command_lower:
                return False
        for pattern in self.safety_patterns['pattern_restrictions']:
            if re.search(pattern, command):
                return False
        is_allowed = any(
            service in command_lower 
            for service in self.safety_patterns['allowed_services']
        )
        return is_allowed
        
    def _get_generic_remediation(self, finding: Dict) -> RemediationPlan:
        return RemediationPlan(
            finding_id=finding.get('finding_id', 'unknown'),
            priority=finding.get('severity', 'medium'),
            summary=f"Remediate: {finding.get('title')}",
            steps=[
                RemediationStep(1, "Inspect the configuration properties", "Review why finding was flagged", "5 minutes", "medium"),
                RemediationStep(2, "Apply standard AWS security hardening", "Reduce attack surface area", "10 minutes", "medium")
            ],
            validation=["Verify configuration in AWS console"],
            confidence=0.70,
            estimated_effort="15 minutes",
            references=[]
        )
