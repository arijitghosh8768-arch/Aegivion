import jwt
import logging
from typing import Callable, Awaitable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.database import SessionLocal
from app.services.security_audit_service import log_security_event

logger = logging.getLogger("security_audit_middleware")

class SecurityAuditMiddleware(BaseHTTPMiddleware):
    """
    Automated security interceptor that captures security-relevant HTTP responses
    (401 Unauthorized, 403 Forbidden, 429 Too Many Requests) and logs them into `security_events`.
    """
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)

        # Inspect status code for security-relevant occurrences
        if response.status_code in (401, 403, 429):
            client_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("user-agent", "unknown")
            path = request.url.path
            method = request.method

            # Extract user & org from JWT if present
            user_id = None
            org_id = None
            role = None
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                try:
                    payload = jwt.decode(token, options={"verify_signature": False})
                    user_id = payload.get("sub")
                    org_id = payload.get("org")
                    role = payload.get("role")
                except Exception:
                    pass

            # Classify event type
            if response.status_code == 401:
                event_type = "UNAUTHENTICATED_ACCESS"
                action = f"{method}:{path}:401_unauthenticated"
            elif response.status_code == 403:
                event_type = "UNAUTHORIZED_ACCESS"
                action = f"{method}:{path}:403_forbidden"
            else:  # 429
                event_type = "RATE_LIMIT_EXCEEDED"
                action = f"{method}:{path}:429_rate_limited"

            actor_data = {
                "ip": client_ip,
                "user_id": user_id,
                "role": role,
                "user_agent": user_agent[:150]
            }
            target_data = {
                "endpoint": path,
                "method": method
            }
            meta_data = {
                "status_code": response.status_code,
                "query_params": str(request.query_params)
            }

            # Safe database write in isolated session
            try:
                db = SessionLocal()
                try:
                    log_security_event(
                        db=db,
                        event_type=event_type,
                        action=action,
                        organization_id=org_id,
                        provider="app_middleware",
                        actor=actor_data,
                        target=target_data,
                        metadata=meta_data
                    )
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"[SecurityAuditMiddleware] Error writing security event: {e}")

        return response

