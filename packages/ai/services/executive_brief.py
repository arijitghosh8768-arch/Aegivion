from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
import json
import logging
from security.engine.risk_engine_v2 import RiskScore
from ai.services.llm_provider import get_llm_provider

logger = logging.getLogger(__name__)

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
    citations: List[Dict[str, Any]] = field(default_factory=list)

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
            'generated_at': self.generated_at,
            'citations': self.citations
        }

class ExecutiveBriefService:
    """Generate executive security briefs using real or fallback LLM providers"""
    
    def __init__(self, llm_provider=None, risk_engine=None):
        self.llm_provider = llm_provider or get_llm_provider()
        self.risk_engine = risk_engine
    
    async def generate_brief(
        self,
        findings: List[Dict],
        risk_scores: Dict[str, Any],
        correlations: List[Dict],
        scan_health: Dict,
        audience: str = 'executive',
        compliance_summary: Optional[Dict[str, Any]] = None
    ) -> ExecutiveBrief:
        """Generate executive security brief with LLM narrative synthesis"""
        
        # 1. Aggregate data
        aggregated = self._aggregate_data(findings, risk_scores, correlations, scan_health, compliance_summary)
        
        # 2. Build deterministic top priorities & quick wins
        top_priorities = self._build_top_priorities(findings, risk_scores, correlations)
        quick_wins = self._identify_quick_wins(findings, risk_scores)
        
        # 3. Generate structured narrative with LLM
        llm_synthesis = await self._synthesize_with_llm(aggregated, top_priorities, quick_wins, audience)
        
        # 4. Generate long-term actions
        long_term = llm_synthesis.get("long_term_actions") or await self._generate_long_term_actions(aggregated)
        
        # 5. Build citations
        citations = []
        for p in top_priorities[:5]:
            for fid in p.finding_ids:
                citations.append({"source": "finding_id", "value": fid, "context": p.title})
        
        return ExecutiveBrief(
            posture=self._determine_posture(aggregated),
            executive_summary=llm_synthesis.get('summary', f"Security posture assessment completed. Found {aggregated['total_findings']} active issues."),
            technical_summary=llm_synthesis.get('technical_summary', f"Assessment identified {aggregated['severity_counts']['critical']} critical and {aggregated['severity_counts']['high']} high issues."),
            top_priorities=top_priorities[:5],
            quick_wins=quick_wins[:3],
            long_term_actions=long_term[:5],
            coverage_note=scan_health.get('coverage_note', 'Full assessment completed.'),
            confidence=0.92,
            generated_at=datetime.utcnow().isoformat(),
            citations=citations
        )
    
    def _aggregate_data(
        self,
        findings: List[Dict],
        risk_scores: Dict[str, Any],
        correlations: List[Dict],
        scan_health: Dict,
        compliance_summary: Optional[Dict[str, Any]] = None
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
            severity = str(finding.get('severity', 'info')).lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        total_findings = len(findings)
        overall_risk = 0
        
        scores = []
        for rs in risk_scores.values():
            if hasattr(rs, 'score'):
                scores.append(rs.score)
            elif isinstance(rs, dict):
                scores.append(rs.get('score', 0))
            else:
                try:
                    scores.append(int(rs))
                except (ValueError, TypeError):
                    scores.append(0)
                    
        if scores:
            overall_risk = sum(scores) // len(scores)
        
        return {
            'total_findings': total_findings,
            'severity_counts': severity_counts,
            'overall_risk': overall_risk,
            'correlation_count': len(correlations),
            'scan_health': scan_health,
            'compliance_summary': compliance_summary or {},
            'has_high_severity': severity_counts['critical'] > 0 or severity_counts['high'] > 0
        }

    async def _synthesize_with_llm(
        self,
        aggregated: Dict,
        top_priorities: List[TopPriority],
        quick_wins: List[QuickWin],
        audience: str
    ) -> Dict[str, Any]:
        """Calls LLM provider to synthesize a grounded executive brief narrative"""
        if not self.llm_provider:
            return {
                'summary': f"Security assessment completed. Found {aggregated['total_findings']} active issues with an overall risk rating of {aggregated['overall_risk']}/100.",
                'technical_summary': f"Assessment metadata shows {aggregated['total_findings']} findings, including {aggregated['severity_counts']['critical']} critical and {aggregated['severity_counts']['high']} high issues.",
                'long_term_actions': []
            }
            
        prompt = f"""
You are the Chief Information Security Officer (CISO) and Lead Cloud Security Architect at Aegivion.
Analyze the following security environment telemetry and generate an executive security brief.

<evidence>
TOTAL_FINDINGS: {aggregated['total_findings']}
CRITICAL_COUNT: {aggregated['severity_counts']['critical']}
HIGH_COUNT: {aggregated['severity_counts']['high']}
MEDIUM_COUNT: {aggregated['severity_counts']['medium']}
LOW_COUNT: {aggregated['severity_counts']['low']}
OVERALL_RISK_SCORE: {aggregated['overall_risk']}/100
CORRELATED_INCIDENTS: {aggregated['correlation_count']}
COMPLIANCE_STATUS: {json.dumps(aggregated.get('compliance_summary', {}))}
TOP_PRIORITY_ISSUES: {[p.to_dict() for p in top_priorities[:3]]}
QUICK_WINS: {[q.to_dict() for q in quick_wins[:3]]}
</evidence>

Output requirements:
Return ONLY a valid JSON object with EXACTLY the following structure:
{{
  "summary": "High-level executive narrative of posture, main risks, and business impact (2-3 sentences)",
  "technical_summary": "Technical deep dive into attack surface and architecture gaps (2-3 sentences)",
  "long_term_actions": [
    "Strategic recommendation 1",
    "Strategic recommendation 2"
  ]
}}
Do NOT include markdown formatting or backticks around the json.
"""
        try:
            import inspect
            res = self.llm_provider.generate(prompt)
            if inspect.iscoroutine(res):
                response_text = await res
            elif inspect.iscoroutinefunction(self.llm_provider.generate):
                response_text = await self.llm_provider.generate(prompt)
            else:
                response_text = res
            
            if hasattr(response_text, 'text'):
                raw = response_text.text
            elif hasattr(response_text, 'content'):
                raw = response_text.content
            else:
                raw = str(response_text)
                
            clean = raw.strip()
            if clean.startswith("```json"):
                clean = clean[7:]
            if clean.startswith("```"):
                clean = clean[3:]
            if clean.endswith("```"):
                clean = clean[:-3]
            clean = clean.strip()
            
            data = json.loads(clean)
            if isinstance(data, dict) and "summary" in data:
                return data
        except Exception as e:
            logger.warning(f"Executive brief LLM synthesis fallback triggered: {e}")
            
        return {
            'summary': f"Security assessment completed. Environment exhibits an overall risk rating of {aggregated['overall_risk']}/100 across {aggregated['total_findings']} findings ({aggregated['severity_counts']['critical']} critical).",
            'technical_summary': f"Identified {aggregated['severity_counts']['critical']} critical and {aggregated['severity_counts']['high']} high vulnerabilities. Remediation of identified attack paths is recommended.",
            'long_term_actions': [
                "Implement least-privilege IAM guardrails and enforce mandatory MFA",
                "Automate continuous CSPM drift scanning and posture reconciliation"
            ]
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
