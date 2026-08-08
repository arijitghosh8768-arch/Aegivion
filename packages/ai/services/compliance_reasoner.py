from typing import Dict, Any, List
from ai.services.llm_provider import get_llm_provider

class ComplianceReasonerService:
    """Generate grounded compliance explanation plan summaries with strict assessment boundaries"""

    def __init__(self):
        self.llm = get_llm_provider()

    async def explain_control(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Explain control failure or status based strictly on deterministic observed facts"""
        code = control.get("control_code")
        title = control.get("title")
        status = control.get("status", "NOT_ASSESSED")
        resources = control.get("affected_resources", [])
        evidence_refs = control.get("evidence_refs", [])
        
        prompt = f"""
        Analyze the compliance status of this AWS Security Control:
        Control Code: {code}
        Title: {title}
        Status: {status}
        Affected Resources: {resources}
        Evidence References: {evidence_refs}

        Return a JSON object containing the detailed explanation. Follow these strict grounding rules:
        - Never state that a cyberattack, breach, or compromise has occurred unless explicitly proven.
        - Treat all potential paths and exposures as conditional scenarios ("could", "would").
        - Always include assessment limitations, stating that this is an automated technical configuration check, not an audit opinion.
        - Link to validation steps (e.g. running a re-scan).

        Desired output format:
        {{
            "summary": "Short 1-2 sentence description of what the control check represents.",
            "why_failed": "Reasoning for FAIL or NOT_ASSESSED status, else describe compliance validation.",
            "security_relevance": "Why this control matters to general cloud security posture.",
            "affected_resources": ["list", "of", "resources"],
            "evidence_summary": ["statement of facts supported by EV reference"],
            "recommended_action": "High-level guidance on how to resolve.",
            "validation": "Validation actions like re-scanning.",
            "limitations": [
                "Automated check only; not an official audit certification or legal statement."
            ]
        }}
        """
        
        try:
            res = await self.llm.generate_json(prompt)
            # Ensure the AI did not modify the authoritative status
            res["status"] = status
            res["control_code"] = code
            return res
        except Exception:
            # Fallback
            return {
                "status": status,
                "control_code": code,
                "summary": f"Automated check summary for {title}.",
                "why_failed": "Detailed evidence was unavailable or check failed.",
                "security_relevance": "Protects cloud identity and access perimeter.",
                "affected_resources": resources,
                "evidence_summary": [f"Fact verified via {ref}" for ref in evidence_refs],
                "recommended_action": "Verify resources in your AWS account.",
                "validation": "Correct the posture in AWS and trigger a new scanning cycle.",
                "limitations": [
                    "Aegivion automated check is configuration-only and does not constitute a certified SOC 2/CIS audit."
                ]
            }
