from typing import Dict, Any, List, Optional
import inspect

class RemediationPlannerService:
    """Remediation planner generating safe implementation playbooks for cloud administrators"""

    def __init__(self, llm_provider=None):
        self.llm_provider = llm_provider

    async def generate_plan(self, remediation_id: str) -> Dict[str, Any]:
        """Generate structured step-by-step guidance to resolve the security breakpoint"""
        
        prompt = self._build_prompt(remediation_id)
        
        # Build safe fallback
        fallback = {
            "title": "Restrict public network ingress rule",
            "priority": "P1",
            "summary": "This remediation addresses public exposure of port 22 on the EC2 instance, breaking the attack path from the Internet.",
            "immediate_action": "Modify the inbound security group rule to restrict TCP/22 to trusted administrative networks.",
            "console_steps": [
                "Open the AWS EC2 Console.",
                "Navigate to Security Groups and select the affected group.",
                "Choose Inbound Rules and click Edit.",
                "Locate the port 22 rule and replace the unrestricted source 0.0.0.0/0 with your approved CIDR range.",
                "Save rules."
            ],
            "cli_guidance": [
                "Review the existing security group rules:",
                "aws ec2 describe-security-groups --group-ids <security-group-id>",
                "Revoke the public SSH access rule:",
                "aws ec2 revoke-security-group-ingress --group-id <security-group-id> --protocol tcp --port 22 --cidr 0.0.0.0/0",
                "Authorize access only for trusted administrative networks:",
                "aws ec2 authorize-security-group-ingress --group-id <security-group-id> --protocol tcp --port 22 --cidr <approved-admin-cidr>"
            ],
            "iac_guidance": [
                "Locate your security group resource definition in Terraform (aws_security_group_rule):",
                "resource \"aws_security_group_rule\" \"admin_ssh\" {",
                "  type        = \"ingress\"",
                "  from_port   = 22",
                "  to_port     = 22",
                "  protocol    = \"tcp\"",
                "  cidr_blocks = [\"<approved-admin-cidr>\"] # Avoid using 0.0.0.0/0",
                "  security_group_id = aws_security_group.example.id",
                "}"
            ],
            "validation_steps": [
                "Run a new scan in Aegivion.",
                "Confirm that the exposure edge between Internet and the EC2 workload is removed.",
                "Confirm that finding AWS-SG-001 transitions from open to resolved."
            ],
            "rollback_considerations": [
                "Ensure approved administrators retain VPC or VPN connectivity before revoking public ingress rules to prevent lockout."
            ],
            "long_term_prevention": [
                "Implement continuous posture checks.",
                "Restrict security group modifications to trusted CI/CD pipelines."
            ],
            "uncertainty": [
                "Aegivion cannot verify business operational requirements for port 22 connectivity."
            ]
        }

        if not self.llm_provider:
            return fallback

        try:
            res = self.llm_provider.generate(prompt)
            if inspect.iscoroutine(res):
                response_text = await res
            elif inspect.iscoroutinefunction(self.llm_provider.generate):
                response_text = await self.llm_provider.generate(prompt)
            else:
                response_text = res
            
            if hasattr(response_text, 'content'):
                text = response_text.content
            else:
                text = str(response_text)
                
            validated = self._validate_and_sanitize(text, fallback)
            return validated
        except Exception:
            return fallback

    def _build_prompt(self, remediation_id: str) -> str:
        return f"""
        Generate a multi-step security remediation plan for:
        REMEDIATION ID: {remediation_id}
        
        Strict rules for plan:
        1. Keep plans conditional and advisory (use "should", "recommend").
        2. DO NOT state that a breach has occurred.
        3. Parameterize environment-specific CIDRs and IDs using angle brackets (< >).
        4. Detail validation steps and rollback considerations.
        
        Return a JSON matching this exact structure:
        {{
            "title": "...",
            "priority": "...",
            "summary": "...",
            "immediate_action": "...",
            "console_steps": ["..."],
            "cli_guidance": ["..."],
            "iac_guidance": ["..."],
            "validation_steps": ["..."],
            "rollback_considerations": ["..."],
            "long_term_prevention": ["..."],
            "uncertainty": ["..."]
        }}
        """

    def _validate_and_sanitize(self, response_text: str, fallback: Dict) -> Dict:
        import json
        try:
            if "{" in response_text:
                json_str = response_text[response_text.find("{"):response_text.rfind("}")+1]
                data = json.loads(json_str)
            else:
                return fallback
        except Exception:
            return fallback

        # Grounding: reject absolute statements about exploitation/compromise
        prohibited_phrases = ["compromised", "breached", "attacker exploited", "stole credentials"]
        
        for k in ["summary", "immediate_action"]:
            text_val = data.get(k, "").lower()
            if any(phrase in text_val for phrase in prohibited_phrases):
                data[k] = fallback[k]

        return data
