from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from security.engine.risk_engine_v2 import RiskScore

@dataclass
class TopPriority:
    rank: int
    title: str
    risk_score: int
    finding_ids: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class QuickWin:
    rank: int
    title: str
    estimated_effort: str  # quick, medium, complex
    impact: str  # high, medium, low
    finding_ids: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ExecutiveBrief:
    posture: str  # critical_risk, high_risk, moderate_risk, low_risk
    executive_summary: str
    technical_summary: str
    top_priorities: List[TopPriority]
    quick_wins: List[QuickWin]
    long_term_actions: List[str]
    coverage_note: str
    confidence: float
    generated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'posture': self.posture,
            'executive_summary': self.executive_summary,
            'technical_summary': self.technical_summary,
            'top_priorities': [tp.to_dict() for tp in self.top_priorities],
            'quick_wins': [qw.to_dict() for qw in self.quick_wins],
            'long_term_actions': self.long_term_actions,
            'coverage_note': self.coverage_note,
            'confidence': self.confidence,
            'generated_at': self.generated_at
        }

class ExecutiveBriefService:
    """Generate executive security briefs"""
    
    def __init__(self, llm_provider=None, risk_engine=None):
        self.llm_provider = llm_provider
        self.risk_engine = risk_engine
    
    async def generate_brief(
        self,
        findings: List[Dict],
        risk_scores: Dict[str, RiskScore],
        correlations: List[Dict],
        scan_health: Dict,
        audience: str = 'executive'
    ) -> ExecutiveBrief:
        """Generate executive security brief"""
        
        # 1. Aggregate data
        aggregated = self._aggregate_data(findings, risk_scores, correlations, scan_health)
        
        # 2. Generate summary with AI
        summary = await self._generate_summary(aggregated, audience)
        
        # 3. Build top priorities
        top_priorities = self._build_top_priorities(findings, risk_scores, correlations)
        
        # 4. Identify quick wins
        quick_wins = self._identify_quick_wins(findings, risk_scores)
        
        # 5. Generate long-term actions
        long_term = await self._generate_long_term_actions(aggregated)
        
        return ExecutiveBrief(
            posture=self._determine_posture(aggregated),
            executive_summary=summary.get('executive', 'Security brief unavailable'),
            technical_summary=summary.get('technical', ''),
            top_priorities=top_priorities[:5],
            quick_wins=quick_wins[:3],
            long_term_actions=long_term[:5],
            coverage_note=scan_health.get('coverage_note', 'Full assessment completed.'),
            confidence=0.90,
            generated_at=datetime.utcnow().isoformat()
        )
    
    def _aggregate_data(
        self,
        findings: List[Dict],
        risk_scores: Dict[str, RiskScore],
        correlations: List[Dict],
        scan_health: Dict
    ) -> Dict[str, Any]:
        """Aggregate data"""
        
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        total_findings = len(findings)
        overall_risk = 0
        
        # Calculate average risk score
        scores = [rs.score if hasattr(rs, 'score') else rs.get('score', 0) if isinstance(rs, dict) else int(rs) for rs in risk_scores.values()]
        if scores:
            overall_risk = sum(scores) // len(scores)
        
        return {
            'total_findings': total_findings,
            'severity_counts': severity_counts,
            'overall_risk': overall_risk,
            'correlation_count': len(correlations),
            'scan_health': scan_health,
            'has_high_severity': severity_counts['critical'] > 0 or severity_counts['high'] > 0
        }
    
    async def _generate_summary(self, aggregated: Dict, audience: str) -> Dict:
        """Generate AI summary"""
        if not self.llm_provider:
            return {
                'executive': f"Security assessment completed. Found {aggregated['total_findings']} active issues with an overall risk rating of {aggregated['overall_risk']}/100.",
                'technical': f"Assessment metadata shows {aggregated['total_findings']} findings, including {aggregated['severity_counts']['critical']} critical and {aggregated['severity_counts']['high']} high issues."
            }
            
        try:
            prompt = self._build_prompt(aggregated, audience)
            import inspect
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
                
            return self._parse_summary(text, audience)
        except Exception:
            return {
                'executive': f"Security assessment completed. Found {aggregated['total_findings']} active issues with an overall risk rating of {aggregated['overall_risk']}/100.",
                'technical': f"Assessment metadata shows {aggregated['total_findings']} findings, including {aggregated['severity_counts']['critical']} critical and {aggregated['severity_counts']['high']} high issues."
            }
    
    def _build_prompt(self, aggregated: Dict, audience: str) -> str:
        """Build prompt for summary generation"""
        return f"""
        Generate a security summary for this AWS environment.
        
        ENVIRONMENT:
        Total Findings: {aggregated['total_findings']}
        Critical: {aggregated['severity_counts']['critical']}
        High: {aggregated['severity_counts']['high']}
        Medium: {aggregated['severity_counts']['medium']}
        Low: {aggregated['severity_counts']['low']}
        
        Overall Risk Score: {aggregated['overall_risk']}
        
        Correlations: {aggregated['correlation_count']}
        
        Scan Coverage: {aggregated['scan_health'].get('coverage_percentage', 0)}%
        
        AUDIENCE: {audience.upper()}
        
        Generate a concise summary focusing on:
        - Overall security posture
        - Most critical issues
        - Required actions
        
        Keep it professional and evidence-based.
        """
    
    def _parse_summary(self, response_text: str, audience: str) -> Dict:
        """Parse AI response"""
        return {
            'executive': response_text[:500],
            'technical': response_text
        }
    
    def _build_top_priorities(
        self,
        findings: List[Dict],
        risk_scores: Dict[str, RiskScore],
        correlations: List[Dict]
    ) -> List[TopPriority]:
        """Build top priorities from data"""
        priorities = []
        
        scored_findings = []
        for finding in findings:
            finding_id = finding.get('finding_id', finding.get('id'))
            score_obj = risk_scores.get(finding_id)
            score_val = score_obj.score if hasattr(score_obj, 'score') else score_obj.get('score', 0) if isinstance(score_obj, dict) else int(score_obj) if score_obj else 0
            
            scored_findings.append({
                'finding': finding,
                'score': score_val,
                'factors_count': len(score_obj.factors) if hasattr(score_obj, 'factors') else 1
            })
        
        scored_findings.sort(key=lambda x: x['score'], reverse=True)
        
        for idx, item in enumerate(scored_findings[:5], 1):
            finding = item['finding']
            priorities.append(TopPriority(
                rank=idx,
                title=finding.get('title', 'Security issue'),
                risk_score=item['score'],
                finding_ids=[finding.get('finding_id', finding.get('id'))],
                reason=f"Scored {item['score']}/100 from asset exposure and severity variables."
            ))
        
        return priorities
    
    def _identify_quick_wins(self, findings: List[Dict], risk_scores: Dict[str, RiskScore]) -> List[QuickWin]:
        """Identify quick wins"""
        quick_wins = []
        
        for finding in findings:
            finding_id = finding.get('finding_id', finding.get('id'))
            score_obj = risk_scores.get(finding_id)
            score_val = score_obj.score if hasattr(score_obj, 'score') else score_obj.get('score', 0) if isinstance(score_obj, dict) else int(score_obj) if score_obj else 0
            
            if score_val >= 50:
                title = finding.get('title', '')
                if any(kw in title.lower() for kw in ['ssh', 'rdp', 'mfa', 'access']):
                    quick_wins.append(QuickWin(
                        rank=len(quick_wins) + 1,
                        title=title,
                        estimated_effort='quick',
                        impact='high',
                        finding_ids=[finding_id]
                    ))
        
        return quick_wins
    
    async def _generate_long_term_actions(self, aggregated: Dict) -> List[str]:
        """Generate long-term actions"""
        return [
            "Implement continuous monitoring for cloud security",
            "Review and update IAM policies regularly",
            "Enable comprehensive logging and monitoring"
        ]
    
    def _determine_posture(self, aggregated: Dict) -> str:
        """Determine overall posture"""
        if aggregated['severity_counts']['critical'] > 0:
            return 'critical_risk'
        elif aggregated['severity_counts']['high'] > 2:
            return 'high_risk'
        elif aggregated['total_findings'] > 10:
            return 'moderate_risk'
        else:
            return 'low_risk'
