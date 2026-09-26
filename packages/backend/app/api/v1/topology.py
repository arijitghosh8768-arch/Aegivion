from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.database import get_db
from app.repositories import AssetRepository

router = APIRouter()

@router.get("/")
def get_topology(
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve REAL network topology nodes and edges"""
    user_org_id = get_current_organization(current_user, db)

    try:
        # 1. Query assets from Repository
        asset_repo = AssetRepository(db)
        assets = asset_repo.get_by_organization(user_org_id)

        if not assets:
            return {"nodes": [], "edges": []}

        nodes = []
        for asset in assets:
            nodes.append({
                "id": str(getattr(asset, "provider_resource_id", "")),
                "type": str(getattr(asset, "resource_type", "unknown")),
                "label": str(getattr(asset, "name", "") or getattr(asset, "provider_resource_id", "")),
                "provider": str(getattr(asset, "provider", "aws")).lower()
            })

        edges = []
        # In a real environment, we'd also pull relationships. We assume they are stored inside 'relationships' JSONB or a separate table.
        for asset in assets:
            rels = getattr(asset, "relationships", [])
            if isinstance(rels, list):
                for rel in rels:
                    if isinstance(rel, dict) and "target" in rel:
                        edges.append({
                            "source": str(getattr(asset, "provider_resource_id", "")),
                            "target": rel["target"],
                            "type": rel.get("type", "connected_to")
                        })

        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        return {"nodes": [], "edges": [], "error": str(e), "message": "Failed to retrieve topology"}
