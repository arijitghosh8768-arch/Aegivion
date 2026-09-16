from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
from app.core.security import get_current_user
from app.database.supabase_client import supabase

router = APIRouter()

@router.get("")
def list_events(current_user: Dict[str, Any] = Depends(get_current_user), limit: int = 50):
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if not user_org_id:
        raise HTTPException(status_code=403, detail="No organization context")

    try:
        result = supabase.table("security_events").select("*").eq("organization_id", user_org_id).order('event_timestamp', desc=True).limit(limit).execute()
        return {"events": result.data if result.data else []}
    except Exception as e:
        return {"events": [], "error": str(e)}

@router.post("")
def ingest_event(event_data: dict, current_user: Dict[str, Any] = Depends(get_current_user)):
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    
    event_data["organization_id"] = user_org_id
    try:
        res = supabase.table("security_events").insert(event_data).execute()
        return res.data[0] if res.data else {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
