from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.database import get_db
from app.database.supabase_client import supabase
from app.repositories.asset_repository import AssetRepository
from app.repositories.security_event_repository import SecurityEventRepository

router = APIRouter()

@router.get("/overview")
def get_twin_overview(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns the organization-scoped security digital twin overview.
    """
    user_org_id = get_current_organization(current_user, db)
    
    asset_repo = AssetRepository(db)
    event_repo = SecurityEventRepository(supabase)
    
    # 1. Fetch assets
    try:
        assets = asset_repo.get_all(user_org_id)
        asset_count = len(assets)
        # Mocking critical assets for now, usually it comes from risk engine
        critical_assets = sum(1 for a in assets if getattr(a, "criticality", "UNKNOWN") == "HIGH")
    except Exception:
        asset_count = 0
        critical_assets = 0
        
    # 2. Fetch identities
    # Assume a generic count logic if not fully implemented in DB
    try:
        identities_result = supabase.table("identities").select("id", count="exact").eq("organization_id", user_org_id).execute()
        identities = identities_result.count or 0
    except Exception:
        identities = 0
        
    # 3. Relationships
    try:
        rel_result = supabase.table("relationships").select("id", count="exact").eq("organization_id", user_org_id).execute()
        relationships = rel_result.count or 0
    except Exception:
        relationships = 0

    # 4. Security Events
    events = event_repo.get_recent_by_organization(user_org_id, 100)
    events_count = len(events)
    
    return {
        "assets": asset_count,
        "identities": identities,
        "relationships": relationships,
        "security_events": events_count,
        "recent_changes": 0, # Implement later with SecurityChange repo
        "critical_assets": critical_assets
    }
