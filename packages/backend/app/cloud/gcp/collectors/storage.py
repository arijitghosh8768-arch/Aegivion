import logging
from typing import Dict, Any, List
from .base import BaseGCPCollector

logger = logging.getLogger(__name__)

class StorageBucketCollector(BaseGCPCollector):
    def __init__(self, credentials, project_id: str):
        super().__init__(credentials, project_id)
        self.collector_name = "gcp_storage_bucket"
        try:
            from googleapiclient.discovery import build
            self.client = build('storage', 'v1', credentials=self.credentials, cache_discovery=False)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            request = self.client.buckets().list(project=self.project_id)
            while request is not None:
                response = request.execute()
                for bucket in response.get('items', []):
                    env = self._build_envelope(
                        asset_id=bucket.get('id'),
                        resource_type="gcp_storage_bucket",
                        region=bucket.get('location', 'global'),
                        name=bucket.get('name'),
                        configuration=bucket,
                        relationships=[]
                    )
                    envelopes.append(env.model_dump())
                request = self.client.buckets().list_next(previous_request=request, previous_response=response)
        except Exception as e:
            logger.error(f"Error collecting GCP Storage Buckets: {e}")
        return envelopes
