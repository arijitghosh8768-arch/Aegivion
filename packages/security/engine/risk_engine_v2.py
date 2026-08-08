from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    MODERATE = "moderate"
    LOW = "low"

@dataclass
class RiskFactor:
    type: str
    value: Any
    contribution: int
    description: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class RiskScore:
    score: int  # 0-100
    level: RiskLevel
    confidence: float  # 0.0-1.0
    factors: List[RiskFactor]
    calculated_at: str
    engine_version: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value,
            "confidence": self.confidence,
            "factors": [f.to_dict() for f in self.factors],
            "calculated_at": self.calculated_at,
            "engine_version": self.engine_version
        }

class RiskEngineV2:
    """Explainable risk scoring engine"""
    
    def __init__(self):
        self.base_severity_weights = {
            'critical': 85,
            'high': 65,
            'medium': 45,
            'low': 20,
            'info': 5
        }
        self.version = "2.0.0"
    
    def calculate_risk(self, finding: Dict, context: Dict, correlations: List[Dict]) -> RiskScore:
        """Calculate explainable risk score"""
        
        factors = []
        score = 0
        
        # 1. Base Severity
        severity = finding.get('severity', 'medium').lower()
        base_score = self.base_severity_weights.get(severity, 45)
        factors.append(RiskFactor(
            type="base_severity",
            value=severity,
            contribution=base_score,
            description=f"Base severity: {severity}",
            evidence=[f"rule: {finding.get('rule_id')}"]
        ))
        score += base_score
        
        # 2. Exposure Modifier
        exposure_score, exposure_evidence = self._calculate_exposure(context)
        if exposure_score > 0:
            exposure_level = context.get('exposure', {}).get('level', 'unknown')
            factors.append(RiskFactor(
                type="exposure",
                value=exposure_level,
                contribution=exposure_score,
                description=f"Exposure: {exposure_level}",
                evidence=exposure_evidence
            ))
            score += exposure_score
        
        # 3. Asset Criticality
        criticality_score = self._calculate_criticality(context)
        if criticality_score > 0:
            crit_level = context.get('criticality', {}).get('level') or context.get('criticality', 'unknown')
            crit_source = context.get('criticality_source') or 'unknown'
            factors.append(RiskFactor(
                type="criticality",
                value=crit_level,
                contribution=criticality_score,
                description=f"Asset criticality: {crit_level}",
                evidence=[f"source: {crit_source}"]
            ))
            score += criticality_score
        
        # 4. Privilege Modifier
        privilege_score, privilege_evidence = self._calculate_privilege(context, finding)
        if privilege_score > 0:
            priv_level = context.get('privilege', {}).get('level', 'unknown')
            factors.append(RiskFactor(
                type="privilege",
                value=priv_level,
                contribution=privilege_score,
                description=f"Privilege level: {priv_level}",
                evidence=privilege_evidence
            ))
            score += privilege_score
        
        # 5. Correlation Modifier
        correlation_score = self._calculate_correlation(correlations)
        if correlation_score > 0:
            factors.append(RiskFactor(
                type="correlation",
                value=len(correlations),
                contribution=correlation_score,
                description=f"Related correlations: {len(correlations)}",
                evidence=[f"correlation_ids: {[c.get('correlation_id', c.get('id', '')) for c in correlations]}"]
            ))
            score += correlation_score
        
        # 6. Clamp score
        score = max(0, min(100, score))
        
        # 7. Apply collection confidence adjustment
        confidence = self._calculate_confidence(context, factors)
        
        # 8. Determine level
        if score >= 90:
            level = RiskLevel.CRITICAL
        elif score >= 70:
            level = RiskLevel.HIGH
        elif score >= 50:
            level = RiskLevel.MEDIUM
        elif score >= 30:
            level = RiskLevel.MODERATE
        else:
            level = RiskLevel.LOW
        
        return RiskScore(
            score=score,
            level=level,
            confidence=confidence,
            factors=factors,
            calculated_at=datetime.utcnow().isoformat(),
            engine_version=self.version
        )
    
    def _calculate_exposure(self, context: Dict) -> tuple:
        """Calculate exposure modifier"""
        exposure = context.get('exposure', {})
        level = exposure.get('level', 'private') if isinstance(exposure, dict) else exposure
        
        if level == 'internet_exposed':
            evidence = exposure.get('evidence', []) if isinstance(exposure, dict) else []
            return 12, evidence
        elif level == 'restricted_external':
            evidence = exposure.get('evidence', []) if isinstance(exposure, dict) else []
            return 5, evidence
        else:
            return 0, []
    
    def _calculate_criticality(self, context: Dict) -> int:
        """Calculate criticality modifier"""
        criticality = context.get('criticality', {})
        level = criticality.get('level', 'unknown') if isinstance(criticality, dict) else criticality
        
        if level == 'mission_critical':
            return 10
        elif level == 'high':
            return 7
        elif level == 'normal':
            return 2
        else:
            return 0
    
    def _calculate_privilege(self, context: Dict, finding: Dict) -> tuple:
        """Calculate privilege modifier"""
        # Only apply privilege to identity findings
        resource_type = finding.get('resource_type')
        if resource_type not in ['iam_user', 'iam_role']:
            return 0, []
        
        privilege = context.get('privilege', {})
        level = privilege.get('level', 'unknown') if isinstance(privilege, dict) else privilege
        
        if level == 'administrative':
            evidence = privilege.get('evidence', []) if isinstance(privilege, dict) else []
            return 10, evidence
        elif level == 'elevated':
            evidence = privilege.get('evidence', []) if isinstance(privilege, dict) else []
            return 6, evidence
        elif level == 'standard':
            evidence = privilege.get('evidence', []) if isinstance(privilege, dict) else []
            return 2, evidence
        else:
            return 0, []
    
    def _calculate_correlation(self, correlations: List[Dict]) -> int:
        """Calculate correlation modifier"""
        if not correlations:
            return 0
        
        total = 0
        for corr in correlations:
            c_dict = corr if isinstance(corr, dict) else corr.to_dict()
            if c_dict.get('severity') == 'critical':
                total += 5
            elif c_dict.get('severity') == 'high':
                total += 3
            
            confidence = c_dict.get('confidence', 0.8)
            # handle string confidence like 'confirmed'
            if isinstance(confidence, str):
                confidence_val = 0.95 if confidence == 'confirmed' else 0.8
            else:
                confidence_val = float(confidence)
            total = int(total * confidence_val)
        
        return min(15, total)  # Cap at 15
    
    def _calculate_confidence(self, context: Dict, factors: List[RiskFactor]) -> float:
        """Calculate overall confidence"""
        base_confidence = 0.90
        
        # Adjust based on collection status
        collection = context.get('collection', {})
        collection_status = collection.get('status', 'complete') if isinstance(collection, dict) else context.get('collection_status', 'complete')
        
        if collection_status == 'partial':
            base_confidence -= 0.15
        elif collection_status == 'minimal':
            base_confidence -= 0.30
        
        # Adjust based on number of factors
        if len(factors) < 3:
            base_confidence -= (3 - len(factors)) * 0.05
        
        # Adjust based on evidence completeness
        has_exposure_evidence = any(f.type == 'exposure' and f.evidence for f in factors)
        if not has_exposure_evidence:
            base_confidence -= 0.05
        
        return max(0.50, min(0.99, base_confidence))
    
    def explain_score(self, risk_score: RiskScore) -> Dict:
        """Generate human-readable explanation"""
        factors_desc = []
        for factor in risk_score.factors:
            factors_desc.append({
                'type': factor.type,
                'description': factor.description,
                'contribution': factor.contribution,
                'evidence': factor.evidence
            })
        
        return {
            'score': risk_score.score,
            'level': risk_score.level.value,
            'confidence': risk_score.confidence,
            'summary': f"Risk score {risk_score.score}/100 - {risk_score.level.value.upper()}",
            'factors': factors_desc,
            'calculation': {
                'total': risk_score.score,
                'components': [f['contribution'] for f in factors_desc],
                'engine_version': risk_score.engine_version
            }
        }
