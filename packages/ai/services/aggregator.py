from typing import Dict, Any

class AIContextAggregator:
    @staticmethod
    def build_context(finding: Dict[str, Any], asset: Dict[str, Any]) -> str:
        """
        Builds a deterministic, structured, AI-ready context prompt block from finding and asset details.
        Enforces that the AI MUST NOT invent evidence or assume compromises.
        """
        evidence = finding.get("evidence", {})
        risk_score = finding.get("risk_score", 50)
        mitre = finding.get("mitre", "N/A")
        
        # Build strict deterministic prompt context
        context = f"""[AEGIVION SECURITY CONTEXT DATA - FOR AI REASONING]
CRITICAL INSTRUCTION FOR AI ANALYST:
You are an expert security analysis AI. You must ONLY reason based on the explicit EVIDENCE provided below. 
You MUST NOT invent evidence, assume compromise occurred, or fabricate details. Stick strictly to the factual configuration details.

---
FINDING DETAILS:
- Finding ID: {finding.get("finding_id")}
- Title: {finding.get("title")}
- Rule ID: {finding.get("rule_id")}
- Severity: {finding.get("severity")}
- Calculated Risk Score: {risk_score}/100

ASSET DETAILS:
- Asset ID: {asset.get("asset_id")}
- Provider: {asset.get("provider")}
- Type: {asset.get("type")}
- Region: {asset.get("region")}
- Name: {asset.get("name")}

CONFIGURATION EXPOSURE & EVIDENCE:
"""
        for key, val in evidence.items():
            context += f"- {key}: {val}\n"
            
        if mitre != "N/A":
            context += f"\nMITRE ATT&CK CONTEXT:\n- Reference: {mitre}\n"

        context += "\n--- END OF CONTEXT DATA ---"
        return context
