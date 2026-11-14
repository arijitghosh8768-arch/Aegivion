from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from app.database.session import current_tenant_org_id
from app.core.security import SecurityService

class TenantContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware that inspects the incoming request's Authorization header,
    decodes the JWT access token (if present), and sets the current_tenant_org_id ContextVar
    so that downstream database sessions automatically enforce PostgreSQL Row-Level Security (RLS).
    """
    async def dispatch(self, request: Request, call_next):
        token_org_id = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
            try:
                security_service = SecurityService()
                payload = security_service.verify_token(token, token_type="access")
                role = (payload.get("role") or "").lower().replace(" ", "")
                if role == "superadmin":
                    token_org_id = "bypass"
                else:
                    token_org_id = payload.get("org") or payload.get("org_id") or payload.get("organization_id")
            except Exception:
                # If token is invalid or expired, downstream auth dependencies will handle 401
                pass

        # Set the tenant context for this async execution flow
        token_reset = current_tenant_org_id.set(str(token_org_id) if token_org_id else None)
        try:
            response = await call_next(request)
            return response
        finally:
            current_tenant_org_id.reset(token_reset)

