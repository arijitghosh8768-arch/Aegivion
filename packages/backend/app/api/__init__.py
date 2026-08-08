from fastapi import APIRouter
from .v1 import findings, auth, cloud_accounts, explain, integration, google_auth, remediation, risk, brief, relationships, incidents, topology, graph, compliance, reports

api_router = APIRouter()
api_router.include_router(findings.router, prefix="/v1/findings", tags=["Findings"])
api_router.include_router(auth.router, prefix="/v1/auth", tags=["Auth"])
api_router.include_router(google_auth.router, prefix="/v1/auth", tags=["Auth"])
api_router.include_router(cloud_accounts.router, prefix="/v1/cloud-accounts", tags=["Cloud Accounts"])
api_router.include_router(explain.router, prefix="/v1/ai", tags=["AI"])
api_router.include_router(integration.router, prefix="/v1", tags=["Integration"])
api_router.include_router(remediation.router, prefix="/v1/remediation", tags=["Remediation"])
api_router.include_router(risk.router, prefix="/v1/risk", tags=["Risk"])
api_router.include_router(brief.router, prefix="/v1/brief", tags=["Brief"])
api_router.include_router(relationships.router, prefix="/v1/relationships", tags=["Relationships"])
api_router.include_router(incidents.router, prefix="/v1/incidents", tags=["Incidents"])
api_router.include_router(topology.router, prefix="/v1/topology", tags=["Topology"])
api_router.include_router(graph.router, prefix="/v1/attack-graph", tags=["Attack Graph"])
api_router.include_router(compliance.router, prefix="/v1/compliance", tags=["Compliance"])
api_router.include_router(reports.router, prefix="/v1/reports", tags=["Reports"])
