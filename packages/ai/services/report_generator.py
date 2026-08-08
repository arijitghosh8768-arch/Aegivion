import json
from datetime import datetime
from typing import List, Dict, Any
from ai.services.llm_provider import get_llm_provider

class ReportGeneratorService:
    """Grounded AI report generation service utilizing authoritative snapshot metrics"""

    def __init__(self):
        self.llm = get_llm_provider()

    async def generate_report(self, report_type: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = datetime.utcnow().isoformat()
        
        # Pull strict numbers from snapshot
        findings_metrics = snapshot.get("findings", {})
        incident_metrics = snapshot.get("incidents", {})
        asset_metrics = snapshot.get("assets", {})
        compliance_metrics = snapshot.get("compliance", {})
        
        prompt = f"""
        Generate a professional cloud security report of type {report_type}.
        Authoritative Metrics from Aegivion Backend:
        - Critical Findings: {findings_metrics.get('critical', 0)}
        - High Findings: {findings_metrics.get('high', 0)}
        - Medium Findings: {findings_metrics.get('medium', 0)}
        - Low Findings: {findings_metrics.get('low', 0)}
        - Open Incidents: {incident_metrics.get('open', 0)}
        - Investigating Incidents: {incident_metrics.get('investigating', 0)}
        - Total Assets Discovered: {asset_metrics.get('total', 0)}
        - High-Risk Assets: {asset_metrics.get('high_risk', 0)}
        - Compliance Control PASS: {compliance_metrics.get('pass', 0)}
        - Compliance Control FAIL: {compliance_metrics.get('fail', 0)}
        - Compliance Control NOT ASSESSED: {compliance_metrics.get('not_assessed', 0)}

        Return a JSON object containing the report sections. Follow these strict grounding rules:
        - You MUST use the exact numbers supplied above. Do not compute or invent alternative statistics.
        - Never claim a breach or confirmed exploit has occurred unless explicitly proven.
        - Add a section for 'limitations' stating this is an automated configuration assessment.

        Desired output format:
        {{
            "summary": "High-level summary of posture findings, using numbers provided.",
            "priorities": [
                "Detailed priority recommendation 1",
                "Detailed priority recommendation 2"
            ],
            "limitations": [
                "Automated check is configuration-only and does not constitute certified legal validation."
            ]
        }}
        """
        
        try:
            res = await self.llm.generate_json(prompt)
            # Guarantee metrics are injected correctly
            res["metrics"] = {
                "findings": findings_metrics,
                "incidents": incident_metrics,
                "assets": asset_metrics,
                "compliance": compliance_metrics
            }
            res["generated_at"] = timestamp
            return res
        except Exception:
            # Fallback
            return {
                "summary": f"Aegivion {report_type} security report mapping {findings_metrics.get('critical', 0)} critical exposures and {incident_metrics.get('open', 0)} active incident groups.",
                "priorities": [
                    "Restrict administrative port exposure to verified CIDRs.",
                    "Audit high-risk compute access keys and enforce MFA policies."
                ],
                "limitations": [
                    "Aegivion automated checks are based on configuration snapshots. Results do not constitute certified SOC 2 or CIS audit opinions."
                ],
                "metrics": {
                    "findings": findings_metrics,
                    "incidents": incident_metrics,
                    "assets": asset_metrics,
                    "compliance": compliance_metrics
                },
                "generated_at": timestamp
            }
