from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Let preflight OPTIONS requests bypass this middleware
        if request.method == "OPTIONS":
            return await call_next(request)

        response = await call_next(request)
        
        # Inject security headers
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Less restrictive CSP to allow development assets/APIs from localhost and production domains
        response.headers["Content-Security-Policy"] = "default-src 'self' http://localhost:* http://127.0.0.1:* https://*.google.com https://*.googleapis.com https://*.onrender.com https://*.vercel.app; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://accounts.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; frame-src 'self' https://accounts.google.com;"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response
