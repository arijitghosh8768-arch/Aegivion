from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import json
from datetime import datetime

@dataclass
class RootCauseAnalysis:
    finding_id: str
    what_happened: str
    why_detected: str
    evidence: List[str]
    security_significance: str
    technical_impact: str
    business_impact: Optional[str]
    confidence: float
    is_grounded: bool
    reasoning_chain: List[str]

class RootCauseEngine:
    """Generate evidence-grounded root cause analysis"""
    
    def __init__(self, llm_provider):
        self.llm_provider = llm_provider
        
    async def analyze(self, finding: Dict, asset: Dict, evidence: Dict) -> RootCauseAnalysis:
        """Generate root cause analysis with evidence grounding"""
        
        # 1. Build evidence chain
        evidence_chain = self._build_evidence_chain(finding, asset, evidence)
        
        # 2. Build prompt with evidence
        prompt = self._build_prompt(finding, asset, evidence_chain)
        
        # 3. Get AI analysis
        response = await self.llm_provider.generate(prompt)
        
        # 4. Parse and validate
        analysis = self._parse_response(response, finding)
        
        # 5. Validate grounding
        analysis = self._validate_grounding(analysis, evidence_chain)
        
        return analysis
    
    def _build_evidence_chain(self, finding: Dict, asset: Dict, evidence: Dict) -> List[str]:
        """Build chain of evidence facts"""
        chain = []
        
        # Rule evidence
        rule_id = finding.get('rule_id')
        chain.append(f"Rule {rule_id} matched the configuration")
        
        # Asset evidence
        asset_type = asset.get('type')
        asset_id = asset.get('asset_id')
        chain.append(f"Affected asset: {asset_type} {asset_id}")
        
        # Specific evidence
        if evidence.get('protocol'):
            chain.append(f"Protocol: {evidence['protocol']}")
        if evidence.get('from_port') and evidence.get('to_port'):
            chain.append(f"Port range: {evidence['from_port']}-{evidence['to_port']}")
        if evidence.get('sources'):
            sources = ', '.join(evidence['sources'])
            chain.append(f"Sources: {sources}")
        
        # Network context
        if asset.get('type') == 'security_group':
            config = asset.get('configuration', {})
            if config.get('internet_exposed'):
                chain.append("Security group has internet exposure")
            if config.get('ipv6_exposed'):
                chain.append("Security group has IPv6 exposure")
        
        # EC2 context
        if asset.get('type') == 'ec2_instance':
            config = asset.get('configuration', {})
            if config.get('has_public_ip'):
                chain.append("EC2 instance has public IP address")
        
        return chain
    
    def _build_prompt(self, finding: Dict, asset: Dict, evidence_chain: List[str]) -> str:
        """Build prompt with evidence grounding instructions"""
        
        return f"""
        You are Aegivion, an expert cloud security analyst.
        
        Analyze this security finding using ONLY the evidence provided.
        
        FINDING:
        Title: {finding.get('title')}
        Description: {finding.get('description')}
        Severity: {finding.get('severity')}
        
        ASSET:
        Type: {asset.get('type')}
        ID: {asset.get('asset_id')}
        Name: {asset.get('name', 'Unknown')}
        Region: {asset.get('region')}
        
        EVIDENCE CHAIN:
        {json.dumps(evidence_chain, indent=2)}
        
        EVIDENCE GROUNDING RULES:
        1. You may ONLY use facts from the evidence chain
        2. DO NOT claim things not supported by evidence
        3. DO NOT claim exploitation occurred
        4. If evidence is incomplete, state what is missing
        5. Technical impact must be directly linked to evidence
        
        Provide analysis in this JSON format:
        {{
            "what_happened": "Summary of what was detected",
            "why_detected": "Why the rule triggered",
            "evidence": ["List of evidence items used"],
            "security_significance": "Why this matters for security",
            "technical_impact": "Technical consequences (based on evidence)",
            "business_impact": "Business impact (if determinable)",
            "confidence": 0.0-1.0,
            "reasoning_chain": ["Step by step reasoning"]
        }}
        """
    
    def _parse_response(self, response, finding: Dict) -> RootCauseAnalysis:
        """Parse AI response with fallback"""
        try:
            # Handle response objects that might have .content or be strings
            content = response.content if hasattr(response, 'content') else str(response)
            data = json.loads(content)
            return RootCauseAnalysis(
                finding_id=finding.get('finding_id'),
                what_happened=data.get('what_happened', ''),
                why_detected=data.get('why_detected', ''),
                evidence=data.get('evidence', []),
                security_significance=data.get('security_significance', ''),
                technical_impact=data.get('technical_impact', ''),
                business_impact=data.get('business_impact'),
                confidence=float(data.get('confidence', 0.85)),
                is_grounded=True,
                reasoning_chain=data.get('reasoning_chain', [])
            )
        except:
            return self._get_fallback_analysis(finding)
    
    def _get_fallback_analysis(self, finding: Dict) -> RootCauseAnalysis:
        """Fallback analysis when AI fails"""
        return RootCauseAnalysis(
            finding_id=finding.get('finding_id'),
            what_happened=f"Security finding detected: {finding.get('title')}",
            why_detected=f"Rule {finding.get('rule_id')} conditions were met",
            evidence=["Review finding evidence for details"],
            security_significance="Security best practice violation detected",
            technical_impact="Configuration may increase attack surface",
            business_impact=None,
            confidence=0.7,
            is_grounded=False,
            reasoning_chain=["AI analysis unavailable, review finding manually"]
        )
    
    def _validate_grounding(self, analysis: RootCauseAnalysis, evidence_chain: List[str]) -> RootCauseAnalysis:
        """Validate that analysis is grounded in evidence"""
        # Check that evidence items match
        for ev in list(analysis.evidence):
            if not any(ev.lower() in item.lower() for item in evidence_chain):
                analysis.evidence.remove(ev)
        
        # Check for unsupported claims
        prohibited_phrases = ['attack', 'breach', 'compromised', 'hacked', 'exploited']
        if analysis.what_happened:
            for phrase in prohibited_phrases:
                if phrase in analysis.what_happened.lower():
                    analysis.what_happened = analysis.what_happened.replace(phrase, 'detected')
                    analysis.is_grounded = False
        
        return analysis
