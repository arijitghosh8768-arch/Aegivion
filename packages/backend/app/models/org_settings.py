import uuid
from datetime import datetime
from app.database.base import BaseModel

class OrgSettings(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.organization_id = kwargs.get("organization_id")
        self.enabled_cloud_providers = kwargs.get("enabled_cloud_providers", ["aws"])
        self.security_policy = kwargs.get("security_policy", {"require_exception_approval": False, "auto_suppress_non_prod": False})
        self.notification_preferences = kwargs.get("notification_preferences", {"email": True, "slack": False, "severity_threshold": "high"})
        self.ai_features_enabled = kwargs.get("ai_features_enabled", True)
        self.branding = kwargs.get("branding", {"company_name": "", "logo_url": "", "theme_color": ""})
        self.custom_compliance_frameworks = kwargs.get("custom_compliance_frameworks", ["CIS", "SOC2"])

    def dict(self):
        res = super().dict()
        res.update({
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "enabled_cloud_providers": self.enabled_cloud_providers,
            "security_policy": self.security_policy,
            "notification_preferences": self.notification_preferences,
            "ai_features_enabled": self.ai_features_enabled,
            "branding": self.branding,
            "custom_compliance_frameworks": self.custom_compliance_frameworks
        })
        return res
