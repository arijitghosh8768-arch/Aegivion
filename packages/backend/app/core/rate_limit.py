import os
import jwt
import socket
from urllib.parse import urlparse
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

def get_rate_limit_key(request: Request) -> str:
    """
    Generate rate limit key:
    - If user is authenticated, use 'user:{user_id}:{ip}'
    - If unauthenticated, use 'ip:{ip}'
    """
    ip = get_remote_address(request) or "127.0.0.1"
    
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            # Unverified decode just for key generation without blocking crypto overhead
            unverified = jwt.decode(token, options={"verify_signature": False})
            user_id = unverified.get("sub")
            if user_id:
                return f"user:{user_id}:{ip}"
        except Exception:
            pass
            
    return f"ip:{ip}"

def _resolve_storage_uri() -> str:
    redis_url = os.getenv("REDIS_URL")
    if redis_url and redis_url.startswith("redis://"):
        try:
            parsed = urlparse(redis_url)
            host = parsed.hostname or "localhost"
            port = parsed.port or 6379
            # Quick probe check to avoid crashing if Redis is not actually running
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                s.connect((host, port))
            return redis_url
        except Exception:
            # Redis not reachable, fallback gracefully to in-memory
            pass
    return "memory://"

storage_uri = _resolve_storage_uri()

limiter = Limiter(
    key_func=get_rate_limit_key,
    headers_enabled=False,
    storage_uri=storage_uri
)

