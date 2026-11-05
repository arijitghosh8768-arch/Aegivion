import logging
from typing import Dict, Any, List
from .base import BaseGCPCollector

logger = logging.getLogger(__name__)

class InstanceCollector(BaseGCPCollector):
    def __init__(self, credentials, project_id: str):
        super().__init__(credentials, project_id)
        self.collector_name = "gcp_compute_instance"
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
            request = self.client.instances().aggregatedList(project=self.project_id)
            while request is not None:
                response = request.execute()
                for zone, instances_scoped_list in response.get('items', {}).items():
                    instances = instances_scoped_list.get('instances', [])
                    for inst in instances:
                        zone_name = zone.split('/')[-1] if 'zones/' in zone else zone
                        relationships = []
                        
                        # Instance -> Subnet / Network
                        if 'networkInterfaces' in inst:
                            for nic in inst['networkInterfaces']:
                                if 'network' in nic:
                                    relationships.append({
                                        "target_id": nic['network'],
                                        "type": "LOCATED_IN"
                                    })
                                if 'subnetwork' in nic:
                                    relationships.append({
                                        "target_id": nic['subnetwork'],
                                        "type": "LOCATED_IN"
                                    })
                        
                        # Instance -> Service Account
                        if 'serviceAccounts' in inst:
                            for sa in inst['serviceAccounts']:
                                if 'email' in sa:
                                    relationships.append({
                                        "target_id": sa['email'],
                                        "type": "RUNS_AS"
                                    })
                        
                        env = self._build_envelope(
                            asset_id=inst.get('selfLink', str(inst.get('id'))),
                            resource_type="gcp_compute_instance",
                            region=zone_name,
                            name=inst.get('name'),
                            configuration=inst,
                            relationships=relationships
                        )
                        envelopes.append(env.model_dump())
                request = self.client.instances().aggregatedList_next(previous_request=request, previous_response=response)
        except Exception as e:
            logger.error(f"Error collecting GCP Instances: {e}")

        return envelopes
