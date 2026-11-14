from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from pydantic import BaseModel
import uuid

from app.database import get_db
from app.models.organization import Organization
from app.models.audit_log import AuditLog
from app.core.security import get_current_user
from app.api.deps import require_permission
from app.core.tenant import get_current_organization

router = APIRouter()

class OrgSettingsUpdate(BaseModel):
    enabled_cloud_providers: List[str] | None = None
    security_policy: Dict[str, Any] | None = None
    notification_preferences: Dict[str, Any] | None = None
    ai_features_enabled: bool | None = None
    branding: Dict[str, Any] | None = None
    custom_compliance_frameworks: List[str] | None = None

def _get_org_settings_dict(org: Organization) -> Dict[str, Any]:
    raw_settings = org.settings or {}
    return {
        "enabled_cloud_providers": raw_settings.get("enabled_cloud_providers", ["aws"]),
        "security_policy": org.security_policy or raw_settings.get("security_policy", {"require_exception_approval": False, "auto_suppress_non_prod": False}),
        "notification_preferences": raw_settings.get("notification_preferences", {"email": True, "slack": False, "severity_threshold": "high"}),
        "ai_features_enabled": raw_settings.get("ai_features_enabled", True),
        "branding": raw_settings.get("branding", {"company_name": org.name, "logo_url": "", "theme_color": ""}),
        "custom_compliance_frameworks": raw_settings.get("custom_compliance_frameworks", ["CIS", "SOC2"]),
    }

@router.get("/{org_id}/settings")
def get_org_settings(
    org_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_org_id = get_current_organization(current_user, db)
    if str(user_org_id) != str(org_id):
        raise HTTPException(status_code=403, detail="Not authorized to access these settings")

    try:
        oid = uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid organization ID format")

    org = db.query(Organization).filter(Organization.id == oid).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    return {
        "success": True,
        "data": _get_org_settings_dict(org)
    }

@router.patch("/{org_id}/settings", dependencies=[Depends(require_permission("manage_org"))])
def update_org_settings(
    org_id: str,
    request: OrgSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_org_id = get_current_organization(current_user, db)
    if str(user_org_id) != str(org_id):
        raise HTTPException(status_code=403, detail="Not authorized to access these settings")

    try:
        oid = uuid.UUID(org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid organization ID format")

    org = db.query(Organization).filter(Organization.id == oid).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    settings = dict(org.settings or {})
    updated_data = request.dict(exclude_unset=True)

    for key, value in updated_data.items():
        if key == "security_policy":
            org.security_policy = value
        settings[key] = value

    org.settings = settings
    org.updated_by = current_user.get("id")

    audit = AuditLog(
        action="update_org_settings",
        resource_type="OrganizationSettings",
        resource_id=org.id,
        user_id=str(current_user.get("id", "system")),
        organization_id=str(org_id),
        details={"updated_fields": list(updated_data.keys())}
    )
    db.add(audit)

    db.commit()
    db.refresh(org)

    return {
        "success": True,
        "data": _get_org_settings_dict(org)
    }
