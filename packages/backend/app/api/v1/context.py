from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.database import get_db
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.repositories import AssetRepository
from app.models.cloud import CloudAsset, AssetRelationship
from security.models.finding import Finding

router = APIRouter()

@router.get("/assets/{id}/full-context")
def get_asset_full_context(
    id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get data freshness and chat context for an asset, scoped to authenticated organization."""
    user_org_id = get_current_organization(current_user, db)
    
    asset_repo = AssetRepository(db)
    asset = asset_repo.get_by_organization_and_id(user_org_id, id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    findings = db.query(Finding).filter(
        Finding.resource_id == asset.resource_id
    ).all()
    # Filter findings that match organization or tenant assets
    findings = [
        f for f in findings
        if getattr(f, "organization_id", None) is None or str(f.organization_id) == str(user_org_id)
    ]
    
    source_rels = db.query(AssetRelationship).filter(AssetRelationship.source_asset_id == id).all()
    target_rels = db.query(AssetRelationship).filter(AssetRelationship.target_asset_id == id).all()
    
    # Deduplicate relationships based on ID
    rels_dict = {}
    for r in source_rels + target_rels:
        rels_dict[r.id] = r
    relationships = list(rels_dict.values())
    
    return {
        "asset": asset.dict() if hasattr(asset, 'dict') else asset.__dict__,
        "findings": [f.dict() if hasattr(f, 'dict') else f.__dict__ for f in findings],
        "relationships": [r.dict() if hasattr(r, 'dict') else r.__dict__ for r in relationships]
    }
