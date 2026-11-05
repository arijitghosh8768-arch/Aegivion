import logging
from typing import Dict, Any, List
from .base import BaseGCPCollector

logger = logging.getLogger(__name__)

class ProjectCollector(BaseGCPCollector):
    def __init__(self, credentials, project_id: str):
        super().__init__(credentials, project_id)
        self.collector_name = "gcp_project"
        try:
            from googleapiclient.discovery import build
            self.client = build('cloudresourcemanager', 'v1', credentials=self.credentials, cache_discovery=False)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            proj = self.client.projects().get(projectId=self.project_id).execute()
            env = self._build_envelope(
                asset_id=f"projects/{self.project_id}",
                resource_type="gcp_project",
                region="global",
                name=proj.get('name', self.project_id),
                configuration=proj,
                relationships=[]
            )
            envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting GCP Project: {e}")
        return envelopes
