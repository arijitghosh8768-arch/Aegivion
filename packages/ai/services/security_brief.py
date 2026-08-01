from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import json

@dataclass
class TopRisk:
    finding_id: str
    risk_score: int
    title: str
    asset_name: str
    severity: str
    reason: str

@dataclass
class SecurityBrief:
    overall_posture: str  # critical_risk, high_risk, moderate_risk, low_risk
    summary: str
    top_risks: List[TopRisk]
    recommended_priorities: List[str]
    statistics: Dict[str, int]
    confidence: float
    generated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_posture": self.overall_posture,
            "summary": self.summary,
            "top_risks": [asdict(r) for r in self.top_risks],
            "recommended_priorities": self.recommended_priorities,
            "statistics": self.statistics,
            "confidence": self.confidence,
            "generated_at": self.generated_at
        }

class SecurityBriefService:
    def __init__(self, llm_provider, risk_engine):
        self.llm_provider = llm_provider
        self.risk_engine = risk_engine
    
    async def generate_brief(self, cloud_account_id: str, findings: List[Dict], assets: List[Dict]) -> SecurityBrief:
        """Generate an AI-powered security brief for an account"""
        
        # 1. Aggregate statistics
        stats = self._aggregate_statistics(findings)
        
        # 2. Identify top risks
        top_risks = self._identify_top_risks(findings, assets)
        
        # 3. Determine overall posture
        overall_posture = self._determine_posture(top_risks, stats)
        
        # 4. Generate AI summary
        summary = await self._generate_summary(findings, top_risks, stats)
        
        # 5. Generate recommendations
        recommendations = await self._generate_recommendations(findings, top_risks)
        
        # 6. Calculate confidence
        confidence = self._calculate_confidence(findings, assets)
        
        return SecurityBrief(
            overall_posture=overall_posture,
            summary=summary,
            top_risks=top_risks[:5],  # Top 5 risks
            recommended_priorities=recommendations[:5],
            statistics=stats,
            confidence=confidence,
            generated_at=datetime.utcnow().isoformat()
        )
    
    def _aggregate_statistics(self, findings: List[Dict]) -> Dict[str, int]:
        stats = {
            'total_findings': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'open': 0,
            'investigating': 0,
            'mitigated': 0,
            'resolved': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in stats:
                stats[severity] = stats.get(severity, 0) + 1
            
            status = finding.get('status', 'open').lower()
            if status in stats:
                stats[status] = stats.get(status, 0) + 1
        
        stats['critical_risks'] = stats.get('critical', 0)
        stats['high_risks'] = stats.get('high', 0)
        stats['total_risks'] = stats['critical_risks'] + stats['high_risks']
        
        return stats
    
    def _identify_top_risks(self, findings: List[Dict], assets: List[Dict]) -> List[TopRisk]:
        asset_lookup = {asset.get('asset_id'): asset for asset in assets}
        risked_findings = []
        
        for finding in findings:
            asset = asset_lookup.get(finding.get('asset_id'))
            if not asset:
                asset = {
                    'asset_id': finding.get('asset_id'),
                    'type': finding.get('resource_type', 'ec2'),
                    'provider': finding.get('provider', 'aws'),
                    'region': finding.get('region', 'global'),
                    'name': finding.get('resource_name', 'Mock Asset'),
                    'configuration': {}
                }
            
            risk_score = self.risk_engine.calculate_risk_score(finding, asset, {})
            risked_findings.append({
                'finding': finding,
                'asset': asset,
                'risk_score': risk_score
            })
        
        # Sort by risk score
        risked_findings.sort(key=lambda x: x['risk_score'].score, reverse=True)
        
        top_risks = []
        for item in risked_findings[:10]:
            finding = item['finding']
            risk_score = item['risk_score']
            
            top_risks.append(TopRisk(
                finding_id=finding.get('finding_id', finding.get('id', 'unknown')),
                risk_score=risk_score.score,
                title=finding.get('title', 'Unknown finding'),
                asset_name=finding.get('resource_name', item['asset'].get('name', 'Unknown asset')),
                severity=finding.get('severity', 'medium'),
                reason=self._generate_risk_reason(finding, risk_score)
            ))
        
        return top_risks
    
    def _determine_posture(self, top_risks: List[TopRisk], stats: Dict) -> str:
        if not top_risks:
            return 'low_risk'
        critical_risks = [r for r in top_risks if r.risk_score >= 80]
        if critical_risks:
            return 'critical_risk'
        high_risks = [r for r in top_risks if r.risk_score >= 60]
        if high_risks:
            return 'high_risk'
        if stats.get('total_findings', 0) > 10:
            return 'moderate_risk'
        return 'low_risk'
    
    async def _generate_summary(self, findings: List[Dict], top_risks: List[TopRisk], stats: Dict) -> str:
        if not findings:
            return "No security findings detected. Your AWS account appears secure."
        
        context = f"""
        AWS Account Security Summary:
        
        Total Findings: {stats['total_findings']}
        Critical: {stats['critical']}
        High: {stats['high']}
        Medium: {stats['medium']}
        Low: {stats['low']}
        
        Top Risks:
        {self._format_top_risks(top_risks[:3])}
        
        Please provide a concise summary of the overall security posture and key concerns.
        Focus on the most critical issues and their potential business impact.
        """
        try:
            response = self.llm_provider.generate(context)
            # check if string or wrapper object
            if hasattr(response, 'content'):
                return response.content.strip()
            return str(response).strip()
        except Exception:
            return f"AWS account has {stats['total_findings']} findings including {stats['critical']} critical and {stats['high']} high severity issues."
    
    async def _generate_recommendations(self, findings: List[Dict], top_risks: List[TopRisk]) -> List[str]:
        if not top_risks:
            return ["Continue monitoring your AWS account for security issues."]
        
        context = f"""
        Based on the following top security risks, provide specific recommendations:
        
        {self._format_top_risks(top_risks[:5])}
        
        Provide 3-5 specific, actionable recommendations prioritized by risk.
        """
        try:
            response = self.llm_provider.generate(context)
            response_text = response.content if hasattr(response, 'content') else str(response)
            recommendations = response_text.strip().split('\n')
            return [r.strip().lstrip('- 12345.') for r in recommendations if r.strip()][:5]
        except Exception:
            return [
                "Address critical and high severity findings immediately",
                "Review and restrict internet-exposed services",
                "Enable MFA for all console users"
            ]
    
    def _generate_risk_reason(self, finding: Dict, risk_score: Any) -> str:
        severity = finding.get('severity', 'medium')
        title = finding.get('title', '')
        return f"{severity.upper()} risk violation: {title}"
    
    def _format_top_risks(self, top_risks: List[TopRisk]) -> str:
        formatted = []
        for risk in top_risks:
            formatted.append(f"- [{risk.risk_score}] {risk.title} ({risk.asset_name})")
        return '\n'.join(formatted)
    
    def _calculate_confidence(self, findings: List[Dict], assets: List[Dict]) -> float:
        confidence = 0.85
        if not findings:
            confidence = 0.95
        elif len(assets) == 0:
            confidence -= 0.2
        return min(1.0, max(0.0, confidence))
