import json
from datetime import datetime
from typing import List, Dict, Any

class ReportGenerator:
    def __init__(self):
        self.templates = {
            'executive': """# Executive Security Report
Generated: {timestamp}
Organization: {organization}

## Executive Summary
{summary}

## Risk Distribution
- Total Vulnerabilities: {total_findings}
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}
""",
            'technical': """# Technical Security Report
Generated: {timestamp}

## Vulnerability Details
{findings_text}
"""
        }
    
    async def generate_report(self, findings: List[Dict[str, Any]], 
                              report_type: str = 'executive',
                              report_format: str = 'markdown') -> Dict[str, Any]:
        
        timestamp = datetime.utcnow().isoformat()
        org_name = findings[0].get('organization', 'Aegivion Demo Corp') if findings else 'Aegivion Demo Corp'
        
        critical_count = sum(1 for f in findings if f.get('severity', '').lower() == 'critical')
        high_count = sum(1 for f in findings if f.get('severity', '').lower() == 'high')
        medium_count = sum(1 for f in findings if f.get('severity', '').lower() == 'medium')
        low_count = sum(1 for f in findings if f.get('severity', '').lower() == 'low')
        
        summary = f"Security scan identified {len(findings)} open findings across cloud accounts. Immediate remediation is advised for high-severity exposes."
        
        if report_type == 'executive':
            content = self.templates['executive'].format(
                timestamp=timestamp,
                organization=org_name,
                summary=summary,
                total_findings=len(findings),
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count
            )
        else:
            findings_text = ""
            for f in findings:
                findings_text += f"### {f.get('title')}\n- Severity: {f.get('severity')}\n- Resource: {f.get('resource_id')}\n\n"
            content = self.templates['technical'].format(
                timestamp=timestamp,
                findings_text=findings_text
            )
            
        return {
            'content': content,
            'format': report_format,
            'type': report_type,
            'generated_at': timestamp,
            'finding_count': len(findings)
        }
        
    async def _generate_summary(self, findings: List[Dict[str, Any]]) -> str:
        return "Assessment complete."
