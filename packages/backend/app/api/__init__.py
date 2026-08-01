from fastapi import APIRouter
from .v1 import findings, auth, cloud_accounts, explain, integration, google_auth

api_router = APIRouter()
api_router.include_router(findings.router, prefix="/v1/findings", tags=["Findings"])
api_router.include_router(auth.router, prefix="/v1/auth", tags=["Auth"])
api_router.include_router(google_auth.router, prefix="/v1/auth", tags=["Auth"])
api_router.include_router(cloud_accounts.router, prefix="/v1/cloud-accounts", tags=["Cloud Accounts"])
api_router.include_router(explain.router, prefix="/v1/ai", tags=["AI"])
api_router.include_router(integration.router, prefix="/v1", tags=["Integration"])
