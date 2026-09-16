from fastapi import APIRouter, Depends, HTTPException, Query, Body
from typing import Dict, Any, List
from app.database import get_db
from app.core.security import get_current_user
from app.database.supabase_client import supabase

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
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if not user_org_id:
        raise HTTPException(status_code=403, detail="No organization context found")

    try:
        # Supabase Query
        query = supabase.table("cloud_assets").select("*").eq("organization_id", user_org_id)
        
        if provider:
            query = query.eq("provider", provider)
        if resource_type:
            query = query.eq("resource_type", resource_type)
            
        result = query.execute()
        return {"assets": result.data if result.data else []}
    except Exception as e:
        # Graceful fallback if Supabase table is not fully set up yet
        return {"assets": [], "error": str(e), "message": "Supabase table may not exist yet"}

@router.get("/{asset_id}")
def get_asset(
    asset_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    
    try:
        result = supabase.table("cloud_assets").select("*").eq("id", asset_id).eq("organization_id", user_org_id).execute()
        
        if not result.data:
            raise HTTPException(status_code=404, detail="Asset not found")
            
        return result.data[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
