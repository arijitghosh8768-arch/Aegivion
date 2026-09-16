from fastapi import APIRouter, Depends, HTTPException, Body
from typing import Dict, Any, List
from app.core.security import get_current_user
from app.database.supabase_client import supabase
from app.cloud.aws.sync import AWSCloudSync

router = APIRouter()

@router.get("")
def list_cloud_accounts(current_user: Dict[str, Any] = Depends(get_current_user)):
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if not user_org_id:
        raise HTTPException(status_code=403, detail="No organization context found")

    try:
        result = supabase.table("cloud_accounts").select("*").eq("organization_id", user_org_id).execute()
        return {"accounts": result.data if result.data else []}
    except Exception as e:
        return {"accounts": [], "error": str(e), "message": "Supabase table may not exist yet"}

@router.post("")
def add_cloud_account(
    account_data: Dict[str, Any] = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Adds a new real cloud account to Supabase and immediately triggers a sync."""
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    
    provider = account_data.get("provider")
    name = account_data.get("name")
    access_key = account_data.get("aws_access_key")
    secret_key = account_data.get("aws_secret_key")
    
    if not provider or not name:
        raise HTTPException(status_code=400, detail="Provider and name required")
        
    if provider == "aws" and (not access_key or not secret_key):
        raise HTTPException(status_code=400, detail="AWS credentials required")
        
    try:
        # Create the account record
        insert_res = supabase.table("cloud_accounts").insert({
            "organization_id": user_org_id,
            "provider": provider,
            "provider_account_id": account_data.get("provider_account_id", f"acc_{name}"),
            "name": name,
            "status": "SYNCING"
        }).execute()
        
        new_account = insert_res.data[0]
        
        # In a real app, this should be dispatched to a background worker (e.g. Celery / Asyncio task)
        # For this milestone vertical slice, we run it synchronously if AWS
        if provider == "aws":
            sync_worker = AWSCloudSync(
                organization_id=user_org_id,
                cloud_account_id=new_account["id"],
                aws_access_key=access_key,
                aws_secret_key=secret_key
            )
            # Sync happens
            success = sync_worker.run_sync()
            new_account["status"] = "HEALTHY" if success else "FAILED"
            
        return new_account
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
