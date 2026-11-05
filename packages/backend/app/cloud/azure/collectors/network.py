import logging
from typing import Dict, Any, List
from .base import BaseAzureCollector

logger = logging.getLogger(__name__)

class VNetCollector(BaseAzureCollector):
    def __init__(self, credential, subscription_id: str):
        super().__init__(credential, subscription_id)
        self.collector_name = "azure_vnet"
        try:
            from azure.mgmt.network import NetworkManagementClient
            self.client = NetworkManagementClient(self.credential, self.subscription_id)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            vnets = self.client.virtual_networks.list_all()
            for vnet in vnets:
                relationships = []
                
                # Subnets are effectively contained within the VNet.
                # The prompt specifies Subnet -> VNet, so the VNet itself
                # might have CONTAINS relationships, or we just rely on Subnet's LOCATED_IN.
                # Let's add CONTAINS.
                if vnet.subnets:
                    for subnet in vnet.subnets:
                        relationships.append({
                            "target_id": subnet.id,
                            "type": "CONTAINS"
                        })
                
                env = self._build_envelope(
                    asset_id=vnet.id,
                    resource_type="azure_vnet",
                    region=vnet.location,
                    name=vnet.name,
                    configuration=vnet.as_dict() if hasattr(vnet, 'as_dict') else {},
                    relationships=relationships
                )
                envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting VNets: {e}")

        return envelopes

class SubnetCollector(BaseAzureCollector):
    def __init__(self, credential, subscription_id: str):
        super().__init__(credential, subscription_id)
        self.collector_name = "azure_subnet"
        try:
            from azure.mgmt.network import NetworkManagementClient
            self.client = NetworkManagementClient(self.credential, self.subscription_id)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            vnets = self.client.virtual_networks.list_all()
            for vnet in vnets:
                if not vnet.subnets:
                    continue
                for subnet in vnet.subnets:
                    relationships = [{
                        "target_id": vnet.id,
                        "type": "LOCATED_IN"
                    }]
                    
                    if subnet.network_security_group:
                        relationships.append({
                            "target_id": subnet.network_security_group.id,
                            "type": "PROTECTED_BY"
                        })
                        
                    env = self._build_envelope(
                        asset_id=subnet.id,
                        resource_type="azure_subnet",
                        region=vnet.location, # inherit from vnet
                        name=subnet.name,
                        configuration=subnet.as_dict() if hasattr(subnet, 'as_dict') else {},
                        relationships=relationships
                    )
                    envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting Subnets: {e}")

        return envelopes

class NSGCollector(BaseAzureCollector):
    def __init__(self, credential, subscription_id: str):
        super().__init__(credential, subscription_id)
        self.collector_name = "azure_nsg"
        try:
            from azure.mgmt.network import NetworkManagementClient
            self.client = NetworkManagementClient(self.credential, self.subscription_id)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            nsgs = self.client.network_security_groups.list_all()
            for nsg in nsgs:
                relationships = []
                
                if nsg.subnets:
                    for sub in nsg.subnets:
                        relationships.append({
                            "target_id": sub.id,
                            "type": "PROTECTS"
                        })
                if nsg.network_interfaces:
                    for nic in nsg.network_interfaces:
                        relationships.append({
                            "target_id": nic.id,
                            "type": "PROTECTS"
                        })
                
                env = self._build_envelope(
                    asset_id=nsg.id,
                    resource_type="azure_nsg",
                    region=nsg.location,
                    name=nsg.name,
                    configuration=nsg.as_dict() if hasattr(nsg, 'as_dict') else {},
                    relationships=relationships
                )
                envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting NSGs: {e}")

        return envelopes
