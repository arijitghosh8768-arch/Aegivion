import sys
import os

# Ensure sibling packages (security, ai) are in sys.path
app_dir = os.path.dirname(os.path.abspath(__file__))  # app
backend_dir = os.path.dirname(app_dir)  # packages/backend
packages_dir = os.path.dirname(backend_dir)  # packages

if packages_dir not in sys.path:
    sys.path.append(packages_dir)

import uuid
from datetime import datetime
from typing import Any, Optional
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import get_db
from .core.exceptions import AegivionException, aegivion_exception_handler
from .api import api_router

app = FastAPI(
    title="Aegivion API",
    description="Backend API for Aegivion Security Platform",
    version="0.1.0"
)

# Standard API response format
class APIResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    timestamp: str
    request_id: str

# Register Exception Handlers
app.add_exception_handler(AegivionException, aegivion_exception_handler)

# CORS middleware config
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from .middleware.security import SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)

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

@app.get("/health", response_model=APIResponse)
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute("SELECT 1")
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

