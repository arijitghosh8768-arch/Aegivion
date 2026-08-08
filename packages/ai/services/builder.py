from typing import Dict, Any, List, Optional
from datetime import datetime

class IncidentContextBuilder:
    """Incident Context Builder for preparing trusted context for AI reasoning"""

    def __init__(self, version: str = "1.0.0"):
        self.version = version

    def build_context(
        self,
        group_id: str,
        findings: List[Dict],
        assets: List[Dict],
        relationships: List[Dict],
        risk_score: int,
        risk_level: str,
        correlation_strength: str
    ) -> Dict[str, Any]:
        """Compile a highly focused context version for the AI to reason on"""
        
        # 1. Size control: Filter relevant assets and findings
        relevant_finding_ids = set(f.get("finding_id", f.get("id")) for f in findings)
        relevant_asset_ids = set(f.get("asset_id", f.get("resource_id")) for f in findings)

        focused_findings = []
        for f in findings:
            fid = f.get("finding_id", f.get("id"))
            if fid in relevant_finding_ids:
                evidence = f.get("evidence", {})
                focused_findings.append({
                    "finding_id": fid,
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "rule_id": f.get("rule_id"),
                    "evidence_summary": str(evidence)[:300] # Truncate large config values
                })

        focused_assets = []
        for a in assets:
            aid = a.get("asset_id", a.get("resource_id"))
            if aid in relevant_asset_ids:
                tags = a.get("configuration", {}).get("tags", {})
                focused_assets.append({
                    "asset_id": aid,
                    "type": a.get("type"),
                    "provider": a.get("provider"),
                    "tags": tags
                })

        focused_relationships = []
        for r in relationships:
            src = r.get("source_asset_id", r.get("source_id"))
            tgt = r.get("target_asset_id", r.get("target_id"))
            if src in relevant_asset_ids or tgt in relevant_asset_ids:
                focused_relationships.append({
                    "source": src,
                    "relationship": r.get("relationship_type", r.get("type")),
                    "target": tgt,
                    "confidence": r.get("confidence", "CONFIRMED")
                })

        # 2. Fact / evidence grounding list
        observed_facts = []
        for idx, f in enumerate(findings):
            fid = f.get("finding_id", f.get("id"))
            observed_facts.append({
                "fact": f.get("description", f.get("title")),
                "evidence_refs": [f"finding:{fid}:evidence:{idx}"]
            })

        # 3. Known Unknowns (Guardrails to prevent AI from making stuff up)
        unknowns = [
            "whether active exploitation has occurred",
            "whether user credentials have been stolen or compromised",
            "whether data exfiltration has taken place",
            "business ownership contacts not explicitly tagged"
        ]

        return {
            "incident_id": f"INC-CAND-{group_id}",
            "context_version": self.version,
            "generated_at": datetime.utcnow().isoformat(),
            "observed": {
                "findings": focused_findings,
                "assets": focused_assets,
                "relationships": focused_relationships,
                "facts": observed_facts
            },
            "deterministic": {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "correlation_strength": correlation_strength
            },
            "unknowns": unknowns
        }
