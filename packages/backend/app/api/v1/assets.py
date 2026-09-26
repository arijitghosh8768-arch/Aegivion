from fastapi import APIRouter, Depends, HTTPException, Query, Body
from typing import Dict, Any, List
from app.database import get_db
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.repositories import AssetRepository

router = APIRouter()

@router.get("")
def list_assets(
    provider: str = Query(None),
    resource_type: str = Query(None),
    db = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Fetch REAL cloud assets from Supabase PostgreSQL instead of MongoDB.
    Enforces strict organization-level tenant isolation.
    """
    user_org_id = get_current_organization(current_user, db)

    try:
        asset_repo = AssetRepository(db)
        assets = asset_repo.get_by_organization(user_org_id)
        
        if provider:
            assets = [a for a in assets if str(getattr(a, "provider", "")).lower() == provider.lower()]
        if resource_type:
            assets = [a for a in assets if str(getattr(a, "type", "")).lower() == resource_type.lower()]
            
        serialized = []
        for a in assets:
            a_dict = a.dict() if hasattr(a, 'dict') else a.__dict__
            serialized.append(a_dict)
            
        return {"assets": serialized}
    except Exception as e:
        # Graceful fallback if table is not fully set up yet
        return {"assets": [], "error": str(e), "message": "Database may not exist yet"}

@router.get("/{asset_id}")
def get_asset(
    asset_id: str,
    db = Depends(get_db)
):
    user_org_id = get_current_organization(current_user, db)
    
    try:
        asset_repo = AssetRepository(db)
        asset = asset_repo.get_by_organization_and_id(user_org_id, asset_id)
        
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
            
        return asset.dict() if hasattr(asset, 'dict') else asset.__dict__
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
