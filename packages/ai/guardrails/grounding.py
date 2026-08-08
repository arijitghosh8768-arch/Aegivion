from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
import json
import re
from security.engine.risk_engine_v2 import RiskScore

class ClaimType(str, Enum):
    OBSERVED = "observed"
    DETERMINISTIC = "deterministic"
    INFERRED = "inferred"
    UNKNOWN = "unknown"

@dataclass
class GroundedClaim:
    claim: str
    claim_type: ClaimType
    evidence_refs: List[str]
    confidence: float

@dataclass
class GroundedResponse:
    claims: List[GroundedClaim]
    overall_confidence: float
    warnings: List[str]
    is_grounded: bool

class GroundingValidator:
    """Validate AI responses against evidence"""
    
    def __init__(self):
        self.prohibited_phrases = self._load_prohibited_phrases()
        self.required_qualifiers = self._load_required_qualifiers()
    
    def _load_prohibited_phrases(self) -> List[str]:
        """Load phrases that require strong evidence"""
        return [
            'attacker',
            'compromised',
            'breached',
            'hacked',
            'exploited',
            'malware',
            'ransomware',
            'data theft',
            'stolen credentials',
            'confirmed exploitation'
        ]
    
    def _load_required_qualifiers(self) -> List[str]:
        """Load qualifiers for business/impact claims"""
        return [
            'may',
            'could',
            'potentially',
            'depending',
            'if',
            'can',
            'might'
        ]
    
    def validate_response(self, response: Dict, evidence: Dict) -> GroundedResponse:
        """Validate AI response against evidence"""
        claims = []
        warnings = []
        
        # Check each claim
        extracted = self._extract_claims(response)
        for claim in extracted:
            claim_type, confidence, evidence_refs = self._classify_claim(claim, evidence)
            
            # Check for prohibited phrases without evidence
            if self._has_prohibited_phrase(claim['text']):
                if claim_type != ClaimType.OBSERVED and not evidence_refs:
                    warnings.append(f"Unsupported claim: '{claim['text']}'")
                    claim_type = ClaimType.UNKNOWN
                    confidence *= 0.5
            
            # Check for business impact claims
            if self._is_business_impact(claim['text']):
                if not self._has_qualifier(claim['text']):
                    warnings.append(f"Business impact should be qualified: '{claim['text']}'")
            
            claims.append(GroundedClaim(
                claim=claim['text'],
                claim_type=claim_type,
                evidence_refs=evidence_refs,
                confidence=confidence
            ))
        
        # Determine overall grounded status
        is_grounded = len(warnings) == 0 and all(c.claim_type != ClaimType.UNKNOWN for c in claims)
        
        return GroundedResponse(
            claims=claims,
            overall_confidence=sum(c.confidence for c in claims) / len(claims) if claims else 0.5,
            warnings=warnings,
            is_grounded=is_grounded
        )
    
    def _extract_claims(self, response: Dict) -> List[Dict]:
        """Extract individual claims from response"""
        claims = []
        
        if 'root_cause' in response and response['root_cause']:
            claims.append({'text': response['root_cause'], 'source': 'root_cause'})
        if 'technical_impact' in response and response['technical_impact']:
            claims.append({'text': response['technical_impact'], 'source': 'technical_impact'})
        if 'business_impact' in response and response['business_impact']:
            claims.append({'text': response['business_impact'], 'source': 'business_impact'})
        if 'recommendations' in response and response['recommendations']:
            if isinstance(response['recommendations'], list):
                for rec in response.get('recommendations', []):
                    claims.append({'text': rec, 'source': 'recommendation'})
            else:
                claims.append({'text': response['recommendations'], 'source': 'recommendation'})
        
        return claims
    
    def _classify_claim(self, claim: Dict, evidence: Dict) -> Tuple[ClaimType, float, List[str]]:
        """Classify claim based on evidence"""
        text = claim['text'].lower()
        evidence_refs = []
        
        # Check if claim directly matches evidence
        for ev_key, ev_value in evidence.items():
            if str(ev_value).lower() in text:
                evidence_refs.append(f"evidence.{ev_key}")
        
        # Classify based on content
        if any(keyword in text for keyword in ['security group', 'config', 'rule', 'detected', 'mfa', 'public']):
            return ClaimType.OBSERVED, 0.95, evidence_refs
        
        if any(keyword in text for keyword in ['risk', 'score', 'severity', 'impact']):
            return ClaimType.DETERMINISTIC, 0.90, evidence_refs
        
        if any(keyword in text for keyword in ['may', 'could', 'potentially', 'likely']):
            return ClaimType.INFERRED, 0.75, evidence_refs
            
        if any(keyword in text for keyword in ['restrict', 'enable', 'apply', 'implement', 'update', 'remove', 'configure', 'remediate', 'access']):
            return ClaimType.INFERRED, 0.80, evidence_refs
        
        # Fallback based on source
        source = claim.get('source')
        if source in ['technical_impact', 'business_impact', 'recommendation']:
            return ClaimType.INFERRED, 0.70, evidence_refs
        
        return ClaimType.UNKNOWN, 0.50, evidence_refs
    
    def _has_prohibited_phrase(self, text: str) -> bool:
        """Check if text contains prohibited phrases"""
        text_lower = text.lower()
        for phrase in self.prohibited_phrases:
            if phrase in text_lower:
                return True
        return False
    
    def _is_business_impact(self, text: str) -> bool:
        """Check if text is about business impact"""
        business_indicators = ['business', 'financial', 'customer', 'data', 'compliance', 'regulatory']
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in business_indicators)
    
    def _has_qualifier(self, text: str) -> bool:
        """Check if text contains required qualifiers"""
        text_lower = text.lower()
        return any(qualifier in text_lower for qualifier in self.required_qualifiers)

class AIGuardrail:
    """Main AI guardrail system"""
    
    def __init__(self):
        self.grounding_validator = GroundingValidator()
    
    def process_ai_response(self, response: Dict, evidence: Dict, risk_score: RiskScore) -> Dict:
        """Process and validate AI response"""
        
        # 1. Validate against evidence
        grounded = self.grounding_validator.validate_response(response, evidence)
        
        # 2. Ensure risk score is not modified
        if 'risk_score' in response:
            if response['risk_score'] != risk_score.score:
                response['risk_score'] = risk_score.score
        
        # 3. Add grounding information
        response['_grounding'] = {
            'is_grounded': grounded.is_grounded,
            'overall_confidence': grounded.overall_confidence,
            'warnings': grounded.warnings,
            'claims': [
                {
                    'text': c.claim,
                    'type': c.claim_type.value,
                    'confidence': c.confidence,
                    'evidence_refs': c.evidence_refs
                }
                for c in grounded.claims
            ]
        }
        
        # 4. Reject if not grounded (or add warning)
        if not grounded.is_grounded:
            response['_grounded_response'] = False
            response['_warning'] = "Some claims could not be verified against evidence"
        else:
            response['_grounded_response'] = True
        
        return response
