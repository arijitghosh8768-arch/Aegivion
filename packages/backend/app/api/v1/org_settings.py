from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from pydantic import BaseModel

from app.database import get_db
from app.models.org_settings import OrgSettings
from app.models.audit_log import AuditLog
from app.core.security import get_current_user
from app.api.deps import require_permission
import uuid

router = APIRouter()

class OrgSettingsUpdate(BaseModel):
    enabled_cloud_providers: List[str] | None = None
    security_policy: Dict[str, Any] | None = None
    notification_preferences: Dict[str, Any] | None = None
    ai_features_enabled: bool | None = None
    branding: Dict[str, Any] | None = None
    custom_compliance_frameworks: List[str] | None = None

@router.get("/{org_id}/settings")
def get_org_settings(
    org_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if str(user_org_id) != str(org_id):
        raise HTTPException(status_code=403, detail="Not authorized to access these settings")
        
    settings = db.query(OrgSettings).filter(OrgSettings.organization_id == org_id).first()
    
    if not settings:
        # Create default settings if they don't exist
        settings = OrgSettings(organization_id=org_id)
        db.add(settings)
        db.commit()
        db.refresh(settings)
        
    return {
        "success": True,
        "data": {
            "enabled_cloud_providers": settings.enabled_cloud_providers,
            "security_policy": settings.security_policy,
            "notification_preferences": settings.notification_preferences,
            "ai_features_enabled": settings.ai_features_enabled,
            "branding": settings.branding,
            "custom_compliance_frameworks": settings.custom_compliance_frameworks
        }
    }

@router.patch("/{org_id}/settings", dependencies=[Depends(require_permission("manage_org"))])
def update_org_settings(
    org_id: str,
    request: OrgSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if str(user_org_id) != str(org_id):
        raise HTTPException(status_code=403, detail="Not authorized to access these settings")
        
    settings = db.query(OrgSettings).filter(OrgSettings.organization_id == org_id).first()
    if not settings:
        settings = OrgSettings(organization_id=org_id)
        db.add(settings)
        db.commit()
        
    # Update fields
    updated_data = request.dict(exclude_unset=True)
    for key, value in updated_data.items():
        setattr(settings, key, value)
        
    settings.updated_by = current_user.get("id")
    
    # Audit Log
    audit = AuditLog(
        action="update_org_settings",
        resource_type="OrgSettings",
        resource_id=settings.id,
        user_id=str(current_user.get("id", "system")),
        organization_id=str(org_id),
        details={"updated_fields": list(updated_data.keys())}
    )
    db.add(audit)
    
    db.commit()
    db.refresh(settings)
    
    return {
        "success": True,
        "data": {
            "enabled_cloud_providers": settings.enabled_cloud_providers,
            "security_policy": settings.security_policy,
            "notification_preferences": settings.notification_preferences,
            "ai_features_enabled": settings.ai_features_enabled,
            "branding": settings.branding,
            "custom_compliance_frameworks": settings.custom_compliance_frameworks
        }
    }
