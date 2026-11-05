import logging
from typing import Dict, Any, List
from .base import BaseGCPCollector

logger = logging.getLogger(__name__)

class NetworkCollector(BaseGCPCollector):
    def __init__(self, credentials, project_id: str):
        super().__init__(credentials, project_id)
        self.collector_name = "gcp_compute_network"
        try:
            from googleapiclient.discovery import build
            self.client = build('compute', 'v1', credentials=self.credentials, cache_discovery=False)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            request = self.client.networks().list(project=self.project_id)
            while request is not None:
                response = request.execute()
                for net in response.get('items', []):
                    relationships = []
                    if 'subnetworks' in net:
                        for subnet_link in net['subnetworks']:
                            relationships.append({
                                "target_id": subnet_link,
                                "type": "CONTAINS"
                            })
                    env = self._build_envelope(
                        asset_id=net.get('selfLink', str(net.get('id'))),
                        resource_type="gcp_compute_network",
                        region="global",
                        name=net.get('name'),
                        configuration=net,
                        relationships=relationships
                    )
                    envelopes.append(env.model_dump())
                request = self.client.networks().list_next(previous_request=request, previous_response=response)
        except Exception as e:
            logger.error(f"Error collecting GCP Networks: {e}")
        return envelopes

class SubnetworkCollector(BaseGCPCollector):
    def __init__(self, credentials, project_id: str):
        super().__init__(credentials, project_id)
        self.collector_name = "gcp_compute_subnetwork"
        try:
            from googleapiclient.discovery import build
            self.client = build('compute', 'v1', credentials=self.credentials, cache_discovery=False)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            request = self.client.subnetworks().aggregatedList(project=self.project_id)
            while request is not None:
                response = request.execute()
                for region, subnetworks_scoped_list in response.get('items', {}).items():
                    subnets = subnetworks_scoped_list.get('subnetworks', [])
                    for sub in subnets:
                        region_name = region.split('/')[-1] if 'regions/' in region else region
                        relationships = []
                        if 'network' in sub:
                            relationships.append({
                                "target_id": sub['network'],
                                "type": "LOCATED_IN"
                            })
                        env = self._build_envelope(
                            asset_id=sub.get('selfLink', str(sub.get('id'))),
                            resource_type="gcp_compute_subnetwork",
                            region=region_name,
                            name=sub.get('name'),
                            configuration=sub,
                            relationships=relationships
                        )
                        envelopes.append(env.model_dump())
                request = self.client.subnetworks().aggregatedList_next(previous_request=request, previous_response=response)
        except Exception as e:
            logger.error(f"Error collecting GCP Subnetworks: {e}")
        return envelopes

class FirewallCollector(BaseGCPCollector):
    def __init__(self, credentials, project_id: str):
        super().__init__(credentials, project_id)
        self.collector_name = "gcp_compute_firewall"
        try:
            from googleapiclient.discovery import build
            self.client = build('compute', 'v1', credentials=self.credentials, cache_discovery=False)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            request = self.client.firewalls().list(project=self.project_id)
            while request is not None:
                response = request.execute()
                for fw in response.get('items', []):
                    relationships = []
                    if 'network' in fw:
                        relationships.append({
                            "target_id": fw['network'],
                            "type": "PROTECTS"
                        })
                    env = self._build_envelope(
                        asset_id=fw.get('selfLink', str(fw.get('id'))),
                        resource_type="gcp_compute_firewall",
                        region="global",
                        name=fw.get('name'),
                        configuration=fw,
                        relationships=relationships
                    )
                    envelopes.append(env.model_dump())
                request = self.client.firewalls().list_next(previous_request=request, previous_response=response)
        except Exception as e:
            logger.error(f"Error collecting GCP Firewalls: {e}")
        return envelopes
