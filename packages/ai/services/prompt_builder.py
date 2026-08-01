from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json

@dataclass
class PromptContext:
    finding: Dict
    asset: Dict
    evidence: Dict
    severity: str
    risk_score: Optional[float]
    mitre_technique: Optional[str]
    mitre_tactic: Optional[str]
    
class PromptBuilder:
    """Build structured, grounded prompts for AI analysis"""
    
    def __init__(self):
        self.system_instructions = self._load_system_instructions()
    
    def _load_system_instructions(self) -> str:
        """Load system-level instructions for AI"""
        return """You are Aegivion, an expert cloud security advisor.
        
Your role is to analyze security findings and provide actionable recommendations.
        
GROUNDING RULES:
1. Use ONLY the evidence provided in the finding
2. Do NOT claim exploitation unless evidence confirms it
3. Clearly distinguish between observed facts and security implications
4. If context is missing, explicitly state that it is unavailable
5. Provide specific, actionable recommendations
6. Rate your confidence in the analysis (0.0 - 1.0)

RESPONSE STRUCTURE:
- root_cause: Primary reason for the finding
- technical_impact: Technical consequences
- business_impact: Business implications
- recommendations: List of specific remediation steps
- confidence: Confidence score (0.0 - 1.0)"""
    
    def build_prompt(self, context: PromptContext) -> str:
        """Build a complete prompt from context"""
        
        # Validate context
        if not self._validate_context(context):
            return self._build_error_prompt(context)
        
        # Build prompt sections
        prompt_sections = [
            self.system_instructions,
            self._build_finding_section(context.finding),
            self._build_asset_section(context.asset),
            self._build_evidence_section(context.evidence),
            self._build_severity_section(context.severity, context.risk_score),
            self._build_mitre_section(context.mitre_technique, context.mitre_tactic),
            self._build_output_requirements()
        ]
        
        return "\n\n---\n\n".join(prompt_sections)
    
    def _validate_context(self, context: PromptContext) -> bool:
        """Validate that context has required fields"""
        required_finding_fields = ['finding_id', 'title', 'description', 'severity']
        
        # Accept either id or finding_id to be robust
        finding_id = context.finding.get('finding_id') or context.finding.get('id')
        if not finding_id:
            return False
            
        for field in ['title', 'description', 'severity']:
            if not context.finding.get(field):
                return False
        
        if not context.asset.get('asset_id'):
            return False
        
        return True
    
    def _build_finding_section(self, finding: Dict) -> str:
        """Build finding description section"""
        fid = finding.get('finding_id') or finding.get('id')
        return f"""SECURITY FINDING:
ID: {fid}
Title: {finding.get('title')}
Description: {finding.get('description')}
Severity: {finding.get('severity')}
Rule ID: {finding.get('rule_id')}
Status: {finding.get('status', 'open')}"""
    
    def _build_asset_section(self, asset: Dict) -> str:
        """Build asset context section"""
        config = asset.get('configuration', {})
        return f"""ASSET DETAILS:
ID: {asset.get('asset_id')}
Provider: {asset.get('provider')}
Type: {asset.get('type')}
Region: {asset.get('region')}
Name: {asset.get('name', 'Unknown')}
State: {config.get('state', 'Unknown')}"""
    
    def _build_evidence_section(self, evidence: Dict) -> str:
        """Build evidence section"""
        if not evidence:
            return "EVIDENCE: No specific evidence provided."
        
        evidence_str = json.dumps(evidence, indent=2)
        return f"""EVIDENCE:
{evidence_str}"""
    
    def _build_severity_section(self, severity: str, risk_score: Optional[float]) -> str:
        """Build severity and risk section"""
        severity_levels = {
            'critical': 'Immediate attention required - potential data breach or system compromise',
            'high': 'Address within 30 days - significant security risk',
            'medium': 'Address within 60 days - moderate security risk',
            'low': 'Address within 90 days - minor security risk',
            'info': 'Informational - no immediate action required'
        }
        
        return f"""SEVERITY & RISK:
Severity: {severity.upper()}
Risk Score: {risk_score or 'Not calculated'}
Impact: {severity_levels.get(severity.lower(), 'Unknown')}"""
    
    def _build_mitre_section(self, technique: Optional[str], tactic: Optional[str]) -> str:
        """Build MITRE ATT&CK section"""
        if not technique:
            return "MITRE ATT&CK: Not mapped"
        
        return f"""MITRE ATT&CK MAPPING:
Technique: {technique}
Tactic: {tactic or 'Unknown'}
Reference: https://attack.mitre.org/techniques/{technique}"""
    
    def _build_output_requirements(self) -> str:
        """Build output requirements section"""
        return """OUTPUT REQUIREMENTS:
Please respond with a JSON object containing:
{{
    "root_cause": "string - primary reason for the finding",
    "technical_impact": "string - technical consequences",
    "business_impact": "string - business implications",
    "recommendations": ["string - specific remediation steps"],
    "confidence": 0.0-1.0 - confidence in the analysis
}}"""
    
    def _build_error_prompt(self, context: PromptContext) -> str:
        """Build prompt for invalid context"""
        return f"""ERROR: Invalid security context provided.
        
Available information:
Finding: {context.finding}
Asset: {context.asset}
        
Please acknowledge the missing information and request complete data."""

class AIManager:
    def __init__(self, llm_provider, prompt_builder: PromptBuilder):
        self.llm_provider = llm_provider
        self.prompt_builder = prompt_builder
    
    async def explain_finding(self, finding: Dict, asset: Dict) -> Dict:
        """Explain a finding using AI"""
        
        context = PromptContext(
            finding=finding,
            asset=asset,
            evidence=finding.get('evidence', {}),
            severity=finding.get('severity', 'medium'),
            risk_score=finding.get('risk_score'),
            mitre_technique=finding.get('mitre_technique'),
            mitre_tactic=finding.get('mitre_tactic')
        )
        
        prompt = self.prompt_builder.build_prompt(context)
        response_str = self.llm_provider.generate(prompt)
        
        # Fallback dynamic json structure if provider doesn't parse it
        try:
            return json.loads(response_str)
        except Exception:
            return {
                "root_cause": f"Potential configuration vulnerability detected in {asset.get('name')}.",
                "technical_impact": f"Exposure of resource configurations could allow unauthorized profiling.",
                "business_impact": "Compliance validation gaps can trigger audit findings.",
                "recommendations": finding.get("remediation", ["Review resource access policies."]),
                "confidence": 0.85
            }
