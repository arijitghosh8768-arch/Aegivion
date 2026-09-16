from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from app.core.security import get_current_user
from app.database.supabase_client import supabase

router = APIRouter()

@router.get("/")
def get_topology(current_user: Any = Depends(get_current_user)):
    """Retrieve REAL network topology nodes and edges from Supabase"""
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if not user_org_id:
        raise HTTPException(status_code=403, detail="No organization context")

    try:
        # 1. Query assets from Supabase
        assets_res = supabase.table("cloud_assets").select("*").eq("organization_id", user_org_id).execute()
        assets = assets_res.data or []

        if not assets:
            return {"nodes": [], "edges": []}

        nodes = []
        for asset in assets:
            nodes.append({
                "id": asset.get("provider_resource_id"),
                "type": asset.get("resource_type", "unknown"),
                "label": asset.get("name") or asset.get("provider_resource_id"),
                "provider": str(asset.get("provider", "aws")).lower()
            })

        edges = []
        # In a real environment, we'd also pull relationships. We assume they are stored inside 'relationships' JSONB or a separate table.
        for asset in assets:
            rels = asset.get("relationships", [])
            if isinstance(rels, list):
                for rel in rels:
                    if isinstance(rel, dict) and "target" in rel:
                        edges.append({
                            "source": asset.get("provider_resource_id"),
                            "target": rel["target"],
                            "type": rel.get("type", "connected_to")
                        })

        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        return {"nodes": [], "edges": [], "error": str(e), "message": "Supabase table may not exist yet"}
