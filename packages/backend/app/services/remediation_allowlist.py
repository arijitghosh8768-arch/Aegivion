import logging
from typing import Dict, Any, Type
from pydantic import ValidationError

from app.schemas.remediation import (
    EnableS3PublicAccessBlockSchema,
    RevokeSecurityGroupIngressSchema
)

logger = logging.getLogger(__name__)

# Canonical Allowlist mapping action names to strict Pydantic schemas
ALLOWED_ACTION_SCHEMAS: Dict[str, Type] = {
    "ENABLE_S3_PUBLIC_ACCESS_BLOCK": EnableS3PublicAccessBlockSchema,
    "REVOKE_SECURITY_GROUP_INGRESS": RevokeSecurityGroupIngressSchema,
}

# Explicit blocklist of known dangerous or destructive AWS operations
EXPLICIT_FORBIDDEN_OPERATIONS = {
    "DELETE", "DROP", "TERMINATE", "DESTROY", "PURGE", "TRUNCATE", "STOP", "REBOOT",
    "DELETES3BUCKET", "TERMINATEINSTANCE", "DELETESECURITYGROUP", "DELETEUSER",
    "ATTACHUSERPOLICY", "PUTUSERPOLICY", "CREATEACCESSKEY"
}


class RemediationAllowlistService:
    """Enforces zero-trust allowlist and strict parameter schemas for automated remediations."""

    @classmethod
    def is_action_allowed(cls, action_type: str) -> bool:
        if not action_type or not isinstance(action_type, str):
            return False
        normalized = action_type.strip().upper()
        # Check against forbidden keywords
        for forbidden in EXPLICIT_FORBIDDEN_OPERATIONS:
            if forbidden in normalized:
                return False
        return normalized in ALLOWED_ACTION_SCHEMAS

    @classmethod
    def validate_action(cls, action_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates action type and parameters against strict allowlist.
        Returns sanitized and validated parameter dictionary.
        Raises ValueError if action is prohibited or parameters fail validation.
        """
        if not action_type or not isinstance(action_type, str):
            raise ValueError("Action type must be a valid non-empty string.")

        normalized_action = action_type.strip().upper()

        # Check explicit forbidden operations
        for forbidden in EXPLICIT_FORBIDDEN_OPERATIONS:
            if forbidden in normalized_action:
                raise ValueError(
                    f"Action not allowed: Destructive or unauthorized action '{action_type}' is strictly prohibited."
                )

        schema_class = ALLOWED_ACTION_SCHEMAS.get(normalized_action)
        if not schema_class:
            raise ValueError(
                f"Action not allowed: Action '{action_type}' is not in the approved remediation allowlist. "
                f"Approved actions are: {list(ALLOWED_ACTION_SCHEMAS.keys())}."
            )

        # Validate parameters against Pydantic schema
        try:
            validated_obj = schema_class(**(parameters or {}))
            return validated_obj.model_dump()
        except ValidationError as e:
            errors = [f"{err['loc'][0]}: {err['msg']}" for err in e.errors()]
            err_msg = "; ".join(errors)
            logger.warning(f"Remediation parameter validation failed for {action_type}: {err_msg}")
            raise ValueError(f"Invalid remediation parameters for '{action_type}': {err_msg}") from e

