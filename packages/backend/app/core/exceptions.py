from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from fastapi import Request
from fastapi.responses import JSONResponse

class ErrorCode(str, Enum):
    # Auth Errors (1000-1999)
    INVALID_CREDENTIALS = "AUTH001"
    TOKEN_EXPIRED = "AUTH002"
    INSUFFICIENT_PERMISSIONS = "AUTH003"
    
    # Resource Errors (2000-2999)
    RESOURCE_NOT_FOUND = "RES001"
    RESOURCE_ALREADY_EXISTS = "RES002"
    RESOURCE_LOCKED = "RES003"
    
    # Validation Errors (3000-3999)
    VALIDATION_FAILED = "VAL001"
    INVALID_INPUT = "VAL002"
    
    # System Errors (5000-5999)
    DATABASE_ERROR = "SYS001"
    AI_SERVICE_ERROR = "SYS002"
    EXTERNAL_API_ERROR = "SYS003"

class AegivionException(Exception):
    def __init__(
        self,
        message: str,
        error_code: ErrorCode,
        status_code: int = 400,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)

async def aegivion_exception_handler(request: Request, exc: AegivionException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.message,
            "error_code": exc.error_code,
            "details": exc.details,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
