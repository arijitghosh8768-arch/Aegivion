from typing import Dict, Any
from fastapi import Depends, HTTPException
from app.core.security import get_current_user
from app.core.rbac import rbac_service
import logging

# Mock Audit Logger
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

def require_permission(permission: str):
    def permission_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        user_role = current_user.get("role", "viewer")
        if not rbac_service.has_permission(user_role, permission):
            raise HTTPException(status_code=403, detail=f"Missing required permission: {permission}")
        return current_user
    return permission_checker

def log_audit_action(action: str, resource_type: str, resource_id: str, user_id: str, org_id: str, details: Dict[str, Any] = None):
    audit_logger.info(f"AUDIT | action={action} | resource_type={resource_type} | resource_id={resource_id} | user_id={user_id} | org_id={org_id} | details={details}")
