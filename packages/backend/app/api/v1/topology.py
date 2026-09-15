from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
from app.database import get_db
from app.models.cloud import CloudAsset, AssetRelationship
from app.core.security import get_current_user

router = APIRouter()

@router.get("/")
def get_topology(
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """Retrieve network topology nodes and edges with tenant isolation"""
    user_org_id = getattr(current_user, 'organization_id', None)

    # 1. Query assets from DB
    assets = db.query(CloudAsset).all()
    if user_org_id:
        assets = [a for a in assets if str(getattr(a, 'organization_id', '')) == str(user_org_id)]

    # 2. Query relationships from DB
    relationships = db.query(AssetRelationship).all()
    if user_org_id:
        relationships = [r for r in relationships if str(getattr(r, 'organization_id', '')) == str(user_org_id)]

    # Remove Mock Topology fallback to prevent demo data from rendering when DB is empty.
    if not assets:
        return {"nodes": [], "edges": []}

    # Map DB assets/relationships to nodes/edges
    nodes = []
    for asset in assets:
        nodes.append({
            "id": asset.resource_id,
            "type": asset.type,
            "label": asset.name or asset.resource_id
        })

    edges = []
    for rel in relationships:
        edges.append({
            "source": rel.source_asset_id,
            "target": rel.target_asset_id,
            "type": rel.relationship_type
        })

    return {"nodes": nodes, "edges": edges}
