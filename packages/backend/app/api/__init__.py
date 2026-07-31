from fastapi import APIRouter
from .v1 import findings

api_router = APIRouter()
api_router.include_router(findings.router, prefix="/v1/findings", tags=["Findings"])
