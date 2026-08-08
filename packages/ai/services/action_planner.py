from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict

@dataclass
class Action:
    rank: int
    title: str
    priority: str  # critical, high, medium, low
    finding_ids: List[str]
    asset_ids: List[str]
    reason: str
    immediate_actions: List[str]
    validation_steps: List[str]
    estimated_effort: str  # quick, medium, complex
    confidence: float
    status: str = "open"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ActionPlan:
    overall_priority: str
    actions: List[Action]
    quick_wins: List[Action]
    summary: str
    executive_summary: str
    confidence: float
    critical_count: int = 0
    high_count: int = 0
    quick_wins_count: int = 0
    total_actions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_priority": self.overall_priority,
            "actions": [a.to_dict() for a in self.actions],
            "quick_wins": [qw.to_dict() for qw in self.quick_wins],
            "summary": self.summary,
            "executive_summary": self.executive_summary,
            "confidence": self.confidence,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "quick_wins_count": self.quick_wins_count,
            "total_actions": self.total_actions
        }

class ActionPlanner:
    """Prioritize and group remediation actions"""
    
    def __init__(self, llm_provider=None):
        self.llm_provider = llm_provider
    
    def plan_actions(self, findings: List[Dict], correlations: List[Dict], risk_scores: Dict) -> ActionPlan:
        """Generate prioritized action plan"""
        
        # 1. Group related findings
        groups = self._group_findings(findings, correlations)
        
        # 2. Calculate priority for each group
        priority_groups = self._calculate_priorities(groups, risk_scores)
        
        # 3. Sort by priority
        sorted_groups = sorted(priority_groups, key=lambda x: x['priority_score'], reverse=True)
        
        # 4. Generate actions
        actions = self._generate_actions(sorted_groups)
        
        # 5. Identify quick wins
        quick_wins = self._identify_quick_wins(actions)
        
        # 6. Generate summary
        summary = self._generate_summary(actions)
        
        critical_count = sum(1 for a in actions if a.priority == 'critical')
        high_count = sum(1 for a in actions if a.priority == 'high')
        
        return ActionPlan(
            overall_priority=self._determine_overall_priority(actions),
            actions=actions,
            quick_wins=quick_wins,
            summary=summary,
            executive_summary=self._generate_executive_summary(actions, quick_wins),
            confidence=0.92,
            critical_count=critical_count,
            high_count=high_count,
            quick_wins_count=len(quick_wins),
            total_actions=len(actions)
        )
    
    def _group_findings(self, findings: List[Dict], correlations: List[Dict]) -> List[Dict]:
        """Group related findings"""
        groups = []
        used_findings = set()
        
        # Group by correlation
        for correlation in correlations:
            # support dict or dataclass Correlation object
            c_dict = correlation if isinstance(correlation, dict) else correlation.to_dict()
            group = {
                'title': c_dict.get('title'),
                'description': c_dict.get('description'),
                'severity': c_dict.get('severity'),
                'finding_ids': c_dict.get('finding_ids', []),
                'asset_ids': c_dict.get('asset_ids', []),
                'evidence': c_dict.get('evidence', [])
            }
            groups.append(group)
            used_findings.update(group['finding_ids'])
        
        # Add ungrouped findings
        for finding in findings:
            fid = finding.get('finding_id', finding.get('id'))
            if fid not in used_findings:
                groups.append({
                    'title': finding.get('title'),
                    'description': finding.get('description'),
                    'severity': finding.get('severity'),
                    'finding_ids': [fid],
                    'asset_ids': [finding.get('asset_id')],
                    'evidence': finding.get('evidence', [])
                })
        
        return groups
    
    def _calculate_priorities(self, groups: List[Dict], risk_scores: Dict) -> List[Dict]:
        """Calculate priority for each group"""
        for group in groups:
            # Calculate priority score
            finding_ids = group.get('finding_ids', [])
            scores = []
            for fid in finding_ids:
                f_score = risk_scores.get(fid, 50)
                if isinstance(f_score, dict):
                    scores.append(f_score.get('score', 50))
                else:
                    scores.append(f_score)
            
            # Max score determines priority
            max_score = max(scores) if scores else 50
            
            # Consider severity
            severity_multiplier = {
                'critical': 1.5,
                'high': 1.2,
                'medium': 1.0,
                'low': 0.8
            }.get(group.get('severity', 'medium'), 1.0)
            
            priority_score = max_score * severity_multiplier
            
            # Determine priority level
            if priority_score >= 80:
                priority = 'critical'
            elif priority_score >= 60:
                priority = 'high'
            elif priority_score >= 40:
                priority = 'medium'
            else:
                priority = 'low'
            
            group['priority_score'] = priority_score
            group['priority'] = priority
        
        return groups
    
    def _generate_actions(self, sorted_groups: List[Dict]) -> List[Action]:
        """Generate actions from groups"""
        actions = []
        
        for rank, group in enumerate(sorted_groups[:10], start=1):
            action = Action(
                rank=rank,
                title=group.get('title', 'Security finding'),
                priority=group.get('priority', 'medium'),
                finding_ids=group.get('finding_ids', []),
                asset_ids=group.get('asset_ids', []),
                reason=group.get('description', 'Security issue requires remediation'),
                immediate_actions=self._generate_immediate_actions(group),
                validation_steps=[
                    "Verify the fix is applied",
                    "Re-run the security assessment",
                    "Confirm the finding no longer appears"
                ],
                estimated_effort=self._estimate_effort(group),
                confidence=0.9
            )
            actions.append(action)
        
        return actions
    
    def _generate_immediate_actions(self, group: Dict) -> List[str]:
        """Generate immediate actions for a group"""
        title = group.get('title', '').lower()
        
        if 'ssh' in title or 'rdp' in title or 'ingress' in title or 'workload' in title:
            return [
                "Restrict administrative port access to authorized networks",
                "Review and update security group rules",
                "Consider implementing bastion host architecture"
            ]
        elif 'mfa' in title or 'identity' in title:
            return [
                "Enable MFA for the affected identity immediately",
                "Review access requirements",
                "Implement privileged access management"
            ]
        elif 's3' in title or 'bucket' in title:
            return [
                "Enable Block Public Access on the bucket",
                "Review bucket policies and ACLs",
                "Implement encryption and versioning"
            ]
        else:
            return [
                "Review the finding in detail",
                "Verify the configuration in AWS console",
                "Apply appropriate remediation based on best practices"
            ]
    
    def _estimate_effort(self, group: Dict) -> str:
        """Estimate effort for remediation"""
        title = group.get('title', '').lower()
        
        if 'mfa' in title or 'access' in title:
            return 'quick'
        elif 'ssh' in title or 'rdp' in title:
            return 'medium'
        elif 's3' in title or 'bucket' in title:
            return 'medium'
        elif 'policy' in title or 'permission' in title:
            return 'complex'
        else:
            return 'medium'
    
    def _identify_quick_wins(self, actions: List[Action]) -> List[Action]:
        """Identify quick wins"""
        quick_wins = []
        
        for action in actions:
            if action.estimated_effort == 'quick' and action.priority in ['critical', 'high']:
                quick_wins.append(action)
        
        return quick_wins[:3]  # Top 3 quick wins
    
    def _generate_summary(self, actions: List[Action]) -> str:
        """Generate summary of actions"""
        if not actions:
            return "No actions required at this time."
        
        critical_actions = [a for a in actions if a.priority == 'critical']
        high_actions = [a for a in actions if a.priority == 'high']
        
        summary = f"Found {len(critical_actions)} critical and {len(high_actions)} high-priority actions. "
        
        if critical_actions:
            summary += "Critical actions require immediate attention. "
        
        return summary
    
    def _generate_executive_summary(self, actions: List[Action], quick_wins: List[Action]) -> str:
        """Generate executive summary"""
        if not actions:
            return "No security findings detected. Environment appears secure."
        
        critical_count = len([a for a in actions if a.priority == 'critical'])
        high_count = len([a for a in actions if a.priority == 'high'])
        
        summary = f"The environment has {critical_count} critical and {high_count} high-priority security issues. "
        
        if quick_wins:
            summary += f"Quick wins available: {', '.join([q.title for q in quick_wins])}. "
        
        summary += "Priority: Address critical exposures first."
        
        return summary
    
    def _determine_overall_priority(self, actions: List[Action]) -> str:
        """Determine overall priority level"""
        if any(a.priority == 'critical' for a in actions):
            return 'critical'
        elif any(a.priority == 'high' for a in actions):
            return 'high'
        elif actions:
            return 'medium'
        else:
            return 'low'
