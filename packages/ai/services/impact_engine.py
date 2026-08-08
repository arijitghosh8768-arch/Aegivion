from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class TechnicalImpact:
    summary: str
    details: List[str]
    affected_control: str
    attack_surface: str
    severity_technical: str
    confidence: float

@dataclass
class BusinessImpact:
    summary: str
    details: List[str]
    risk_category: str  # data_breach, operational, financial, compliance
    business_context: str
    confidence: float

@dataclass
class ImpactAnalysis:
    finding_id: str
    technical_impact: TechnicalImpact
    business_impact: BusinessImpact
    confidence: float

class ImpactEngine:
    """Generate separated technical and business impact analysis"""
    
    def __init__(self, llm_provider):
        self.llm_provider = llm_provider
        # Load impact templates
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, Any]:
        """Load impact templates by resource type"""
        return {
            "s3_bucket": {
                "technical": {
                    "template": "S3 bucket configuration affects {aspects}.",
                    "controls": {
                        "public_access": "Object storage access controls",
                        "encryption": "Data-at-rest protection",
                        "versioning": "Data recovery and resilience",
                        "logging": "Audit capability"
                    }
                },
                "business": {
                    "categories": {
                        "data_breach": "Unauthorized access to stored objects",
                        "operational": "Disruption to data availability",
                        "compliance": "Potential regulatory non-compliance",
                        "financial": "Cost implications from resource misuse"
                    }
                }
            },
            "iam_user": {
                "technical": {
                    "template": "Identity configuration affects {aspects}.",
                    "controls": {
                        "mfa": "Identity authentication strength",
                        "credentials": "Credential lifecycle management",
                        "permissions": "Access authorization boundaries"
                    }
                },
                "business": {
                    "categories": {
                        "data_breach": "Unauthorized access to resources",
                        "operational": "Disruption to business operations",
                        "compliance": "Access governance requirements"
                    }
                }
            }
        }
    
    async def analyze(self, finding: Dict, asset: Dict, evidence: Dict) -> ImpactAnalysis:
        """Generate technical and business impact analysis"""
        
        resource_type = asset.get('resource_type', asset.get('type', 'unknown'))
        
        # Get resource-specific template
        template = self.templates.get(resource_type, self._get_default_template())
        
        # Build context
        context = self._build_context(finding, asset, evidence)
        
        # Generate impact using AI
        try:
            response = await self.llm_provider.generate(
                self._build_prompt(context, template)
            )
            parsed = self._parse_response(response, finding)
            if parsed:
                return self._validate_impact(parsed, context)
            else:
                return self._get_fallback_impact(finding, asset, evidence)
            
        except Exception as e:
            logger.error(f"Impact analysis failed: {str(e)}")
            return self._get_fallback_impact(finding, asset, evidence)
    
    def _build_context(self, finding: Dict, asset: Dict, evidence: Dict) -> Dict:
        """Build context for impact analysis"""
        return {
            "finding": {
                "title": finding.get('title'),
                "description": finding.get('description'),
                "severity": finding.get('severity'),
                "rule_id": finding.get('rule_id')
            },
            "asset": {
                "type": asset.get('resource_type', asset.get('type')),
                "name": asset.get('name'),
                "region": asset.get('region')
            },
            "evidence": evidence
        }
    
    def _build_prompt(self, context: Dict, template: Dict) -> str:
        """Build prompt for impact analysis"""
        
        return f"""
        Analyze the security impact of this finding.
        
        FINDING:
        Title: {context['finding']['title']}
        Description: {context['finding']['description']}
        Severity: {context['finding']['severity']}
        Rule: {context['finding']['rule_id']}
        
        ASSET:
        Type: {context['asset']['type']}
        Name: {context['asset']['name']}
        Region: {context['asset']['region']}
        
        EVIDENCE:
        {json.dumps(context['evidence'], indent=2)}
        
        Generate TWO separate impact analyses:
        
        1. TECHNICAL IMPACT (for engineers):
           - Technical summary
           - Affected control
           - Attack surface implications
           - Technical details (list)
           - Technical severity (critical/high/medium/low)
           - Confidence (0.0-1.0)
        
        2. BUSINESS IMPACT (for managers):
           - Business summary
           - Risk category (data_breach/operational/financial/compliance)
           - Business context
           - Business details (list)
           - Confidence (0.0-1.0)
        
        RULES:
        1. Use ONLY evidence provided
        2. DO NOT claim business context not supported by evidence
        3. Use conditional language for business impact
        4. Distinguish between technical and business language
        
        Provide response in JSON format:
        {{
            "technical_impact": {{
                "summary": "Technical summary description",
                "details": ["Detail 1", "Detail 2"],
                "affected_control": "Affected security control",
                "attack_surface": "Attack surface description",
                "severity_technical": "technical severity (critical/high/medium/low)",
                "confidence": 0.9
            }},
            "business_impact": {{
                "summary": "Business summary description using conditional language (e.g. may, could, potentially)",
                "details": ["Detail 1", "Detail 2"],
                "risk_category": "risk category (data_breach/operational/financial/compliance)",
                "business_context": "Business context details",
                "confidence": 0.85
            }},
            "confidence": 0.88
        }}
        """
    
    def _parse_response(self, response, finding: Dict) -> Optional[ImpactAnalysis]:
        """Parse AI response with validation"""
        try:
            content = response.content if hasattr(response, 'content') else str(response)
            data = json.loads(content)
            
            tech = data.get('technical_impact', {})
            biz = data.get('business_impact', {})
            
            return ImpactAnalysis(
                finding_id=finding.get('finding_id'),
                technical_impact=TechnicalImpact(
                    summary=tech.get('summary', 'Technical impact analysis unavailable'),
                    details=tech.get('details', []),
                    affected_control=tech.get('affected_control', 'Unknown'),
                    attack_surface=tech.get('attack_surface', 'Unknown'),
                    severity_technical=tech.get('severity_technical', 'medium'),
                    confidence=float(tech.get('confidence', 0.85))
                ),
                business_impact=BusinessImpact(
                    summary=biz.get('summary', 'Business impact analysis unavailable'),
                    details=biz.get('details', []),
                    risk_category=biz.get('risk_category', 'operational'),
                    business_context=biz.get('business_context', ''),
                    confidence=float(biz.get('confidence', 0.80))
                ),
                confidence=float(data.get('confidence', 0.82))
            )
        except:
            return None
    
    def _validate_impact(self, analysis: ImpactAnalysis, context: Dict) -> ImpactAnalysis:
        """Validate impact analysis grounding"""
        # Check if business impact is conditional
        biz_summary = analysis.business_impact.summary.lower()
        
        # Ensure conditional language for business impact
        conditional_phrases = ['if', 'may', 'could', 'can', 'depending', 'potentially']
        has_conditional = any(phrase in biz_summary for phrase in conditional_phrases)
        
        # If no conditional language, add it
        if not has_conditional and "if" not in biz_summary:
            analysis.business_impact.summary = f"Potentially: {analysis.business_impact.summary}"
            analysis.business_impact.confidence *= 0.9
        
        return analysis
    
    def _get_fallback_impact(self, finding: Dict, asset: Dict, evidence: Dict) -> ImpactAnalysis:
        """Fallback impact analysis"""
        return ImpactAnalysis(
            finding_id=finding.get('finding_id'),
            technical_impact=TechnicalImpact(
                summary=f"Technical impact: {finding.get('title')}",
                details=["Review finding evidence for technical details"],
                affected_control="Unknown",
                attack_surface="Unknown",
                severity_technical=finding.get('severity', 'medium'),
                confidence=0.70
            ),
            business_impact=BusinessImpact(
                summary=f"Business impact: Review finding for potential business implications",
                details=["Impact assessment unavailable - manual review required"],
                risk_category="operational",
                business_context="",
                confidence=0.60
            ),
            confidence=0.65
        )
    
    def _get_default_template(self) -> Dict:
        """Default impact template"""
        return {
            "technical": {
                "template": "Configuration affects {aspects}.",
                "controls": {
                    "default": "Security configuration"
                }
            },
            "business": {
                "categories": {
                    "operational": "Operational risk identified",
                    "compliance": "Potential compliance concern",
                    "data_breach": "Potential data exposure risk",
                    "financial": "Potential financial impact"
                }
            }
        }
