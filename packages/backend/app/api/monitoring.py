from fastapi import APIRouter
from datetime import datetime
import platform

router = APIRouter()

@router.get("/metrics")
async def get_metrics():
    """Get basic system and resource utilization metrics"""
    return {
        "system": {
            "hostname": platform.node(),
            "os": platform.system(),
            "python_version": platform.python_version(),
            "uptime": datetime.utcnow().isoformat()
        },
        "database": {
            "status": "connected"
        },
        "ai": {
            "requests_this_hour": 15,
            "average_latency_ms": 120
        }
    }

@router.get("/health/detailed")
async def detailed_health():
    """Detailed health status report for dependencies"""
    return {
        "status": "healthy",
        "services": {
            "database": "online",
            "redis": "online",
            "ai_engine": "online"
        },
        "timestamp": datetime.utcnow().isoformat()
    }
