from fastapi import APIRouter, Depends, HTTPException
from app.database import get_db
from app.models.cloud import CloudAsset, AssetRelationship
from security.models.finding import Finding

router = APIRouter()

@router.get("/assets/{id}/full-context")
def get_asset_full_context(id: str, db = Depends(get_db)):
    """Get data freshness and chat context for an asset."""
    asset = db.query(CloudAsset).filter(CloudAsset.id == id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    findings = db.query(Finding).filter(Finding.resource_id == id).all()
    
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
