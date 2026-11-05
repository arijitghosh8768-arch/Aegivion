import logging
from typing import Dict, Any, List
from .base import BaseGCPCollector

logger = logging.getLogger(__name__)

class ServiceAccountCollector(BaseGCPCollector):
    def __init__(self, credentials, project_id: str):
        super().__init__(credentials, project_id)
        self.collector_name = "gcp_iam_service_account"
        try:
            from googleapiclient.discovery import build
            self.client = build('iam', 'v1', credentials=self.credentials, cache_discovery=False)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            request = self.client.projects().serviceAccounts().list(name=f"projects/{self.project_id}")
            while request is not None:
                response = request.execute()
                for sa in response.get('accounts', []):
                    env = self._build_envelope(
                        asset_id=sa.get('name', str(sa.get('uniqueId'))),
                        resource_type="gcp_iam_service_account",
                        region="global",
                        name=sa.get('email'),
                        configuration=sa,
                        relationships=[]
                    )
                    envelopes.append(env.model_dump())
                request = self.client.projects().serviceAccounts().list_next(previous_request=request, previous_response=response)
        except Exception as e:
            logger.error(f"Error collecting GCP Service Accounts: {e}")
        return envelopes

class IAMPolicyCollector(BaseGCPCollector):
    def __init__(self, credentials, project_id: str):
        super().__init__(credentials, project_id)
        self.collector_name = "gcp_iam_policy"
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
            policy = self.client.projects().getIamPolicy(
                resource=self.project_id, 
                body={}
            ).execute()
            
            # The project IAM policy isn't a single "asset" normally, but bindings inside it are relationships.
            # We will emit one asset for the project policy, but we add CAN_ACCESS relationships for every binding.
            relationships = []
            if 'bindings' in policy:
                for binding in policy['bindings']:
                    for member in binding.get('members', []):
                        if member.startswith('serviceAccount:'):
                            target_id = member.split(':', 1)[1]
                            relationships.append({
                                "target_id": target_id,
                                "type": "ATTACHED_TO"
                            })
                            relationships.append({
                                "target_id": f"projects/{self.project_id}",
                                "type": "CAN_ACCESS"
                            })
                            
            env = self._build_envelope(
                asset_id=f"projects/{self.project_id}/iamPolicy",
                resource_type="gcp_iam_policy",
                region="global",
                name="project-iam-policy",
                configuration=policy,
                relationships=relationships
            )
            envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting GCP IAM Policy: {e}")
        return envelopes
