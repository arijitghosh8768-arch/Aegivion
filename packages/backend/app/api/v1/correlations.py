from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
from app.database import get_db
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.repositories import AssetRepository, FindingRepository
from app.cloud.aws.relationships.engine import RelationshipEngine
from security.correlation.engine import CorrelationEngine, ConfidenceLevel

router = APIRouter()

def _map_correlation_to_chain(corr, idx: int) -> Dict[str, Any]:
    """
    Transforms a security Correlation domain object into the graph-ready
    kill-chain structure expected by the Threat Correlation frontend view.
    """
    corr_dict = corr.to_dict() if hasattr(corr, "to_dict") else corr
    cid = corr_dict.get("correlation_id", f"chain-{idx+1}")
    title = corr_dict.get("title", f"Correlation Chain #{idx+1}")
    severity = str(corr_dict.get("severity", "medium")).lower()

    finding_ids = corr_dict.get("finding_ids", [])
    asset_ids = corr_dict.get("asset_ids", [])
    relationships = corr_dict.get("relationships", [])
    evidence_list = corr_dict.get("evidence", [])

    nodes = []
    edges = []

    # Map findings and assets as nodes
    # If findings exist, create sequential chain nodes
    if finding_ids:
        for f_idx, fid in enumerate(finding_ids):
            node_id = f"{cid}-n{f_idx+1}"
            nodes.append({
                "id": node_id,
                "label": f"Alert: {fid}",
                "tactic": "Correlated Indicator",
                "technique_id": "T1078" if "iam" in fid.lower() or "user" in fid.lower() else "T1059",
                "severity": severity,
                "alert_id": fid,
                "description": corr_dict.get("description", "Correlated security finding"),
                "evidence": [str(e) for e in evidence_list] if evidence_list else [f"Related finding {fid}"]
            })
            if f_idx > 0:
                prev_node_id = f"{cid}-n{f_idx}"
                edges.append({
                    "id": f"{cid}-e{f_idx}",
                    "source": prev_node_id,
                    "target": node_id,
                    "evidence": corr_dict.get("impact", "Shared blast radius / contextual link")
                })
    else:
        # Asset-based chain nodes
        for a_idx, aid in enumerate(asset_ids):
            node_id = f"{cid}-a{a_idx+1}"
            nodes.append({
                "id": node_id,
                "label": f"Asset: {aid}",
                "tactic": "Impacted Resource",
                "technique_id": "T1496",
                "severity": severity,
                "alert_id": aid,
                "description": corr_dict.get("description", "Resource in threat path"),
                "evidence": [str(e) for e in evidence_list] if evidence_list else [f"Impacted asset {aid}"]
            })
            if a_idx > 0:
                prev_node_id = f"{cid}-a{a_idx}"
                edges.append({
                    "id": f"{cid}-e{a_idx}",
                    "source": prev_node_id,
                    "target": node_id,
                    "evidence": "Linked via shared network or identity policy"
                })

    return {
        "id": cid,
        "title": title,
        "severity": severity,
        "alert_count": len(finding_ids) or len(asset_ids),
        "confidence": corr_dict.get("confidence", "derived"),
        "impact": corr_dict.get("impact", ""),
        "recommendations": corr_dict.get("recommendations", []),
        "nodes": nodes,
        "edges": edges,
    }


@router.get("")
@router.get("/")
def get_threat_correlations(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns threat correlation chains for the authenticated user's organization.
    Runs the existing CorrelationEngine against current findings and assets.
    """
    user_org_id = get_current_organization(current_user, db)

    # 1. Fetch organization-isolated assets & findings
    asset_repo = AssetRepository(db)
    finding_repo = FindingRepository(db)

    raw_assets = asset_repo.get_by_organization(user_org_id)
    raw_findings = finding_repo.get_by_organization(user_org_id)

    real_assets = []
    for a in raw_assets:
        real_assets.append({
            "asset_id": getattr(a, "resource_id", str(getattr(a, "id", ""))),
            "provider": getattr(getattr(a, "provider", None), "value", str(getattr(a, "provider", "aws"))),
            "type": getattr(a, "type", "cloud_resource"),
            "region": getattr(a, "region", "global"),
            "name": getattr(a, "name", ""),
            "configuration": getattr(a, "configuration", {}) or {}
        })

    real_findings = []
    for f in raw_findings:
        real_findings.append({
            "finding_id": str(getattr(f, "id", "")),
            "title": getattr(f, "title", "Security Finding"),
            "description": getattr(f, "description", ""),
            "severity": getattr(getattr(f, "severity", None), "value", str(getattr(f, "severity", "medium"))).lower(),
            "status": getattr(getattr(f, "status", None), "value", str(getattr(f, "status", "open"))),
            "asset_id": getattr(f, "resource_id", ""),
            "rule_id": getattr(f, "rule_id", ""),
            "evidence": getattr(f, "evidence", {}) or {}
        })

    # 2. Run existing CorrelationEngine
    rel_engine = RelationshipEngine()
    relationships = rel_engine.build_relationships(real_assets) if real_assets else []

    corr_engine = CorrelationEngine()
    corr_engine.load_data(real_findings, real_assets, relationships)
    calculated_correlations = corr_engine.correlate()

    # 3. Format as chains
    chains = [
        _map_correlation_to_chain(corr, idx)
        for idx, corr in enumerate(calculated_correlations)
    ]

    return {
        "chains": chains,
        "correlations": [c.to_dict() if hasattr(c, "to_dict") else c for c in calculated_correlations],
        "total": len(chains)
    }

