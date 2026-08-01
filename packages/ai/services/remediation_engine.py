from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import logging

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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "priority": self.priority,
            "summary": self.summary,
            "steps": [asdict(s) for s in self.steps],
            "validation": self.validation,
            "confidence": self.confidence,
            "estimated_effort": self.estimated_effort,
            "references": self.references
        }

class RemediationEngine:
    def __init__(self, llm_provider, prompt_builder):
        self.llm_provider = llm_provider
        self.prompt_builder = prompt_builder
        self.fallback_plans = self._load_fallback_plans()
    
    def _load_fallback_plans(self) -> Dict[str, RemediationPlan]:
        """Load fallback remediation plans for common findings"""
        return {
            "AWS-IAM-001": RemediationPlan(
                finding_id="AWS-IAM-001",
                priority="high",
                summary="Enable MFA for console-enabled IAM user",
                steps=[
                    RemediationStep(
                        order=1,
                        action="Enable an MFA device for the IAM user",
                        reason="Console access without MFA is a critical security risk",
                        effort="5 minutes",
                        urgency="immediate"
                    ),
                    RemediationStep(
                        order=2,
                        action="Review whether console access is still required",
                        reason="Remove unnecessary interactive access",
                        effort="10 minutes",
                        urgency="high"
                    )
                ],
                validation=[
                    "Verify MFA device is registered",
                    "Re-run IAM assessment",
                    "Test console access with MFA"
                ],
                confidence=0.95,
                estimated_effort="15 minutes",
                references=[
                    "https://aws.amazon.com/iam/features/mfa/",
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                ]
            ),
            "AWS-IAM-002": RemediationPlan(
                finding_id="AWS-IAM-002",
                priority="medium",
                summary="Rotate old access keys",
                steps=[
                    RemediationStep(
                        order=1,
                        action="Create new access key pair",
                        reason="Rotate keys regularly to reduce exposure",
                        effort="5 minutes",
                        urgency="high"
                    ),
                    RemediationStep(
                        order=2,
                        action="Update applications to use new keys",
                        reason="Ensure services have access during rotation",
                        effort="30 minutes",
                        urgency="high"
                    ),
                    RemediationStep(
                        order=3,
                        action="Deactivate and delete old access keys",
                        reason="Remove unused credentials",
                        effort="5 minutes",
                        urgency="medium"
                    )
                ],
                validation=[
                    "Verify applications work with new keys",
                    "Confirm old keys are deactivated",
                    "Check CloudTrail for key usage"
                ],
                confidence=0.90,
                estimated_effort="40 minutes",
                references=[
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
                ]
            )
        }
    
    async def generate_remediation(self, finding: Dict) -> RemediationPlan:
        """Generate a remediation plan for a finding"""
        rule_id = finding.get('rule_id')
        if rule_id in self.fallback_plans:
            return self.fallback_plans[rule_id]
        
        try:
            prompt = self._build_remediation_prompt(finding)
            response = self.llm_provider.generate(prompt)
            
            parsed = self._parse_ai_response(response, finding)
            validated = self._validate_remediation_plan(parsed)
            return validated
            
        except Exception as e:
            logger.error(f"Remediation generation failed: {str(e)}")
            return self._get_generic_remediation(finding)
    
    def _build_remediation_prompt(self, finding: Dict) -> str:
        return f"""
        Generate a remediation plan for the following security finding:
        
        FINDING:
        Title: {finding.get('title')}
        Description: {finding.get('description')}
        Severity: {finding.get('severity')}
        Resource: {finding.get('resource_type')} ({finding.get('asset_id')})
        
        EVIDENCE:
        {json.dumps(finding.get('evidence', {}), indent=2)}
        
        MITRE ATT&CK:
        Technique: {finding.get('mitre_technique', 'Unknown')}
        Tactic: {finding.get('mitre_tactic', 'Unknown')}
        
        Please provide a structured remediation plan in JSON format with:
        {{
            "priority": "critical/high/medium/low",
            "summary": "Summary of remediation plan",
            "steps": [
                {{
                    "order": 1,
                    "action": "action to take",
                    "reason": "why this is necessary",
                    "effort": "estimated duration (e.g. 5 minutes)",
                    "urgency": "immediate/high/medium/low"
                }}
            ],
            "validation": ["validation steps"],
            "confidence": 0.0-1.0,
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
                references=data.get('references', [])
            )
        except Exception:
            return self._get_generic_remediation(finding)
    
    def _validate_remediation_plan(self, plan: RemediationPlan) -> RemediationPlan:
        for step in plan.steps:
            if not step.action:
                step.action = "Review and remediate the finding"
            if not step.reason:
                step.reason = "Security best practice"
        
        if not plan.validation:
            plan.validation = [
                "Verify the issue is resolved",
                "Re-run security assessment",
                "Monitor for recurrence"
            ]
        return plan
    
    def _get_generic_remediation(self, finding: Dict) -> RemediationPlan:
        return RemediationPlan(
            finding_id=finding.get('finding_id', 'unknown'),
            priority=finding.get('severity', 'medium'),
            summary=f"Remediate: {finding.get('title', 'Security Finding')}",
            steps=[
                RemediationStep(
                    order=1,
                    action="Review the finding in detail",
                    reason="Understand the security issue",
                    effort="10 minutes",
                    urgency="high"
                ),
                RemediationStep(
                    order=2,
                    action="Identify the root cause",
                    reason="Implement the correct fix",
                    effort="30 minutes",
                    urgency="medium"
                ),
                RemediationStep(
                    order=3,
                    action="Apply the remediation",
                    reason="Fix the security issue",
                    effort="1 hour",
                    urgency="medium"
                )
            ],
            validation=[
                "Verify the issue is resolved",
                "Re-run security assessment"
            ],
            confidence=0.70,
            estimated_effort="2 hours",
            references=[]
        )
