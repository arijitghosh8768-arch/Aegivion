import sys
import os

# Ensure sibling packages (security, ai) are in sys.path
app_dir = os.path.dirname(os.path.abspath(__file__))  # app
backend_dir = os.path.dirname(app_dir)  # packages/backend
packages_dir = os.path.dirname(backend_dir)  # packages

if packages_dir not in sys.path:
    sys.path.append(packages_dir)

# Load root environment variables
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(packages_dir), ".env"))

import uuid
from datetime import datetime
from typing import Any, Optional
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from .core.rate_limit import limiter

from .database import get_db
from .core.exceptions import AegivionException, aegivion_exception_handler
from .api import api_router

from prometheus_client import make_asgi_app
from .core.logging import setup_logging
from .middleware.logging import LoggingMiddleware

# Setup structlog
setup_logging()


from contextlib import asynccontextmanager
import asyncio

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start the automation worker
    from app.workers.automation_worker import automation_worker_loop
    worker_task = asyncio.create_task(automation_worker_loop())
    yield
    # Shutdown: Cancel the worker
    worker_task.cancel()

app = FastAPI(
    title="Aegivion API",
    description="Backend API for Aegivion Security Platform",
    version="0.1.0",
    lifespan=lifespan
)


# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


# Standard API response format
class APIResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    timestamp: str
    request_id: str

# Register Exception Handlers
app.add_exception_handler(AegivionException, aegivion_exception_handler)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Import and register Security Headers Middleware first (will execute after CORSMiddleware on responses)
from .middleware.security import SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(LoggingMiddleware)

# CORS middleware config (registered last, so it executes first on requests and last on responses)
allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "https://aegivion.vercel.app",
]
env_origins = os.getenv("ALLOWED_ORIGINS", "")
if env_origins:
    allowed_origins.extend([origin.strip() for origin in env_origins.split(",") if origin.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.vercel\.app",  # Support all Vercel preview deployments
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
)


# Include v1 routes under /api
app.include_router(api_router, prefix="/api")

from .api.monitoring import router as monitoring_router
app.include_router(monitoring_router, prefix="/api")

@app.get("/")
def read_root():
    return {
        "success": True,
        "data": {"message": "Hello World from Aegivion Backend API"},
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": str(uuid.uuid4())
    }

from sqlalchemy import text

@app.get("/health")
def health_check():
    """Lightweight liveness check — Render pings this to confirm the service is up."""
    return {"status": "ok", "success": True}

@app.get("/health/ready", response_model=APIResponse)
def readiness_check(db: Any = Depends(get_db)):
    """Deeper check — confirms the DB connection actually works, not just that the process is running."""
    try:
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return APIResponse(
        success=True,
        data={
            "status": "healthy" if db_status == "healthy" else "degraded",
            "service": "backend",
            "version": "0.1.0",
            "database": db_status
        },
        timestamp=datetime.utcnow().isoformat(),
        request_id=str(uuid.uuid4())
    )

from fastapi import WebSocket, WebSocketDisconnect
from .core.websocket import ws_manager

@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket, user_id: str = "guest"):
    await ws_manager.connect(websocket, user_id)
    try:
        while True:
            # Maintain connection and listen for heartbeat
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, user_id)

