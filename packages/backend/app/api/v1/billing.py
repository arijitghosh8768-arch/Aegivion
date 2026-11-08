from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any, Optional

from app.database import get_db
from app.core.security import get_current_user
from app.core.tenant import get_current_organization
from app.models.organization import Organization, SubscriptionPlan
from app.models.cloud import CloudAccount
from app.models.finding import Finding
from app.models.cloud import CloudAsset

router = APIRouter()

PLAN_LIMITS: Dict[str, Dict[str, Any]] = {
    "free": {
        "max_cloud_accounts": 1,
        "max_assets": 100,
        "max_users": 5,
        "name": "Free Tier",
        "price": "$0/mo"
    },
    "pro": {
        "max_cloud_accounts": 5,
        "max_assets": 1000,
        "max_users": 20,
        "name": "Pro Tier",
        "price": "$299/mo"
    },
    "enterprise": {
        "max_cloud_accounts": 9999,
        "max_assets": 999999,
        "max_users": 9999,
        "name": "Enterprise Tier",
        "price": "$999/mo"
    }
}

class UpgradeRequest(BaseModel):
    tier: str  # 'free', 'pro', 'enterprise'

@router.get("/usage")
def get_usage_and_limits(
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """Returns current resource counts alongside subscription limits for the tenant."""
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if not user_org_id:
        user_org_id = get_current_organization(current_user, db)

    org = db.query(Organization).filter(Organization.id == user_org_id).first()
    plan_key = (org.subscription_plan or "free").lower() if org else "free"
    limits = PLAN_LIMITS.get(plan_key, PLAN_LIMITS["free"])

    # Query counts
    cloud_accounts_count = db.query(CloudAccount).filter(CloudAccount.organization_id == user_org_id).count()
    from app.repositories.asset_repository import AssetRepository
    assets_count = len(AssetRepository(db).get_by_organization(str(user_org_id)))
    findings_count = db.query(Finding).filter(Finding.organization_id == user_org_id).count()

    return {
        "success": True,
        "subscription_plan": plan_key,
        "plan_details": limits,
        "usage": {
            "cloud_accounts": {
                "current": cloud_accounts_count,
                "limit": limits["max_cloud_accounts"],
                "percentage": min(100, round((cloud_accounts_count / limits["max_cloud_accounts"]) * 100)) if limits["max_cloud_accounts"] else 0
            },
            "assets": {
                "current": assets_count,
                "limit": limits["max_assets"],
                "percentage": min(100, round((assets_count / limits["max_assets"]) * 100)) if limits["max_assets"] else 0
            },
            "findings": {
                "current": findings_count
            }
        }
    }

@router.post("/upgrade")
def upgrade_subscription_tier(
    payload: UpgradeRequest,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """Upgrade or switch organization subscription tier."""
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if not user_org_id:
        user_org_id = get_current_organization(current_user, db)

    target_tier = payload.tier.lower().strip()
    if target_tier not in PLAN_LIMITS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid subscription tier '{payload.tier}'. Allowed tiers: {list(PLAN_LIMITS.keys())}"
        )

    org = db.query(Organization).filter(Organization.id == user_org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    org.subscription_plan = target_tier
    db.add(org)
    db.commit()
    db.refresh(org)

    return {
        "success": True,
        "message": f"Successfully updated subscription to {target_tier.capitalize()}",
        "subscription_plan": org.subscription_plan,
        "plan_details": PLAN_LIMITS[target_tier]
    }

