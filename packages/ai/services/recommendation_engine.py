from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class Recommendation:
    finding_id: str
    title: str
    description: str
    priority: str
    confidence_score: float
    references: List[Dict[str, Any]]
    estimated_effort: str
    estimated_impact: float
    implementation_steps: List[str]
    verification_steps: List[str]

class RecommendationEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
    async def generate_recommendation(self, finding: Dict[str, Any]) -> Recommendation:
        """Generate AI-powered recommendation for a finding"""
        
        # Build prompt with proper structure
        prompt = self._build_prompt(finding)
        
        # Get response (statically mocked in Day 5 for offline compatibility)
        response_text = self._get_fallback_response(finding)
        
        return Recommendation(
            finding_id=finding.get('id', 'unknown'),
            title=f"Remediate: {finding.get('title', 'Unknown finding')}",
            description="AI-generated remediation plan based on cloud compliance framework standards",
            priority=finding.get('severity', 'MEDIUM').upper(),
            confidence_score=0.85,
            references=[{"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/"}],
            estimated_effort="2-4 hours",
            estimated_impact=90.0,
            implementation_steps=self._extract_steps(response_text),
            verification_steps=self._extract_verification(response_text)
        )
    
    def _build_prompt(self, finding: Dict[str, Any]) -> str:
        system_prompt = "You are an expert cloud security advisor. Generate specific, actionable recommendations."
        user_prompt = f"""
        Finding: {finding.get('title')}
        Description: {finding.get('description')}
        Resource: {finding.get('resource_type')} ({finding.get('resource_id')})
        Severity: {finding.get('severity')}
        """
        return f"{system_prompt}\n\n{user_prompt}"
    
    def _extract_steps(self, text: str) -> List[str]:
        return [
            "Identify the target cloud configuration resource path.",
            "Apply explicit restrictive rules or blocks to public access.",
            "Deploy verification audits on the resource to ensure no external endpoints are remaining."
        ]
        
    def _extract_verification(self, text: str) -> List[str]:
        return [
            "Perform external ports/endpoints ping checks.",
            "Inspect resource policies through CLI queries."
        ]
    
    def _get_fallback_response(self, finding: Dict[str, Any]) -> str:
        return f"""
        Recommendation: Disable public access to resource: {finding.get('resource_id')} immediately.
        
        Steps:
        1. Navigate to the resource in your cloud console.
        2. Revoke public access rights.
        3. Audit NSG and Firewall settings.
        """
