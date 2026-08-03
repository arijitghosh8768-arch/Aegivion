from datetime import datetime
import enum
from app.database.base import BaseModel

class SubscriptionPlan(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"

class Organization(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = kwargs.get("name")
        self.slug = kwargs.get("slug")
        self.industry = kwargs.get("industry")
        self.subscription_plan = kwargs.get("subscription_plan") or SubscriptionPlan.FREE
        self.owner_id = kwargs.get("owner_id")
        self.settings = kwargs.get("settings") or {}
        self.trial_ends_at = kwargs.get("trial_ends_at")
        self.subscription_ends_at = kwargs.get("subscription_ends_at")
        self.max_users = kwargs.get("max_users") or 5
        self.max_projects = kwargs.get("max_projects") or 1
        self.features = kwargs.get("features") or {
            "advanced_security": False,
            "ai_assistant": False,
            "custom_reports": False,
            "api_access": False
        }
        self.users = []  # Loaded dynamically if needed

    def is_trial_active(self) -> bool:
        if not self.trial_ends_at:
            return False
        t = self.trial_ends_at
        if isinstance(t, str):
            try:
                t = datetime.fromisoformat(t)
            except Exception:
                return False
        return datetime.utcnow() < t

    def can_add_user(self) -> bool:
        return len(self.users) < self.max_users

    def dict(self):
        res = super().dict()
        res.update({
            "name": self.name,
            "slug": self.slug,
            "industry": self.industry,
            "subscription_plan": self.subscription_plan,
            "owner_id": str(self.owner_id) if self.owner_id else None,
            "settings": self.settings,
            "trial_ends_at": self.trial_ends_at.isoformat() if isinstance(self.trial_ends_at, datetime) else self.trial_ends_at,
            "subscription_ends_at": self.subscription_ends_at.isoformat() if isinstance(self.subscription_ends_at, datetime) else self.subscription_ends_at,
            "max_users": self.max_users,
            "max_projects": self.max_projects,
            "features": self.features
        })
        return res

