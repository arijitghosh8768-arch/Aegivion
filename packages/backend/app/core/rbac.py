import os
from typing import List, Dict, Any, Optional
from enum import Enum
from functools import wraps
from fastapi import HTTPException, Depends
import casbin
from .security import get_current_user

class Permission(str, Enum):
    MANAGE_USERS = "manage_users"
    VIEW_USERS = "view_users"
    DELETE_USERS = "delete_users"
    VIEW_FINDINGS = "view_findings"
    MANAGE_FINDINGS = "manage_findings"
    RESOLVE_FINDINGS = "resolve_findings"
    GENERATE_REPORTS = "generate_reports"
    VIEW_REPORTS = "view_reports"
    DELETE_REPORTS = "delete_reports"
    VIEW_ASSETS = "view_assets"
    MANAGE_ASSETS = "manage_assets"
    MANAGE_SETTINGS = "manage_settings"
    MANAGE_INTEGRATIONS = "manage_integrations"
    MANAGE_BILLING = "manage_billing"
    USE_AI_ASSISTANT = "use_ai_assistant"
    MANAGE_KNOWLEDGE = "manage_knowledge"

class RolePolicy:
    POLICIES = {
        "super_admin": ["*"],
        "organization_admin": [
            "manage_users", "view_users", "delete_users",
            "view_findings", "manage_findings", "resolve_findings",
            "generate_reports", "view_reports", "delete_reports",
            "view_assets", "manage_assets", "manage_settings",
            "manage_integrations", "manage_billing", "use_ai_assistant",
            "manage_knowledge"
        ],
        "security_analyst": [
            "view_findings", "manage_findings", "resolve_findings",
            "view_reports", "generate_reports", "view_assets", "use_ai_assistant"
        ],
        "auditor": ["view_findings", "view_reports", "view_assets"],
        "viewer": ["view_findings", "view_reports", "view_assets"]
    }

class RBACService:
    def __init__(self):
        conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rbac_model.conf')
        self.enforcer = casbin.Enforcer(conf_path)
        self._load_policies()
    
    def _load_policies(self):
        """Load default policies in memory"""
        for role, permissions in RolePolicy.POLICIES.items():
            for permission in permissions:
                self.enforcer.add_policy(role, permission, 'allow')
    
    def has_permission(self, user_role: str, permission: str) -> bool:
        """Check if user role has specific permission"""
        if user_role == "super_admin":
            return True
        return self.enforcer.enforce(user_role, permission, 'allow')

rbac_service = RBACService()

def require_permission(permission: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Check dependencies resolving current_user
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(401, "Authentication required")
            
            user_role = current_user.get("role", "viewer")
            if not rbac_service.has_permission(user_role, permission):
                raise HTTPException(403, f"Missing required permission: {permission}")
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator
