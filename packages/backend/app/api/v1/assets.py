from fastapi import APIRouter, Depends, HTTPException, Body
from typing import Dict, Any
from app.database import get_db
from app.models.cloud import CloudAsset
from app.models.audit_log import AuditLog, AuditAction
from app.api.deps import require_permission
from app.core.security import get_current_user


router = APIRouter()

@router.patch("/{asset_id}/context", dependencies=[Depends(require_permission("manage_assets"))])
def update_asset_context(
    asset_id: str,
    context_data: Dict[str, Any] = Body(...),
    db = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update context fields of an asset manually."""
    asset = db.query(CloudAsset).filter(CloudAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if user_org_id and str(getattr(asset, 'organization_id', '')) != str(user_org_id) and getattr(asset, 'organization_id', None) is not None:
        raise HTTPException(status_code=403, detail="Not authorized to access this asset")

        
    allowed_fields = ["environment", "owner", "data_classification", "business_criticality", "department", "application", "internet_exposed", "importance_score"]
    
    updated_fields = {}
    for key, value in context_data.items():
        if key in allowed_fields:
            setattr(asset, key, value)
            updated_fields[key] = value
            
    if updated_fields:
        # Create audit log
        audit = AuditLog(
            action="asset_context_updated", # Using string as it gets saved as string in Mongo
            resource_type="CloudAsset",
            resource_id=asset_id,
            details={"updated_context": updated_fields},
            user_id=str(current_user.get("id", "system")), organization_id=str(user_org_id) if user_org_id else None
        )
        db.add(audit)
        db.commit()
        
    return {"status": "success", "asset": asset.dict()}
