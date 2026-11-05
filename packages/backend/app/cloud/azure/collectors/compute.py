import logging
from typing import Dict, Any, List
from .base import BaseAzureCollector

logger = logging.getLogger(__name__)

class VMCollector(BaseAzureCollector):
    def __init__(self, credential, subscription_id: str):
        super().__init__(credential, subscription_id)
        self.collector_name = "azure_vm"
        try:
            from azure.mgmt.compute import ComputeManagementClient
            self.client = ComputeManagementClient(self.credential, self.subscription_id)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            logger.warning("Azure SDK not installed. Skipping VM collection.")
            return []

        envelopes = []
        try:
            vms = self.client.virtual_machines.list_all()
            for vm in vms:
                relationships = []
                
                # VM -> NIC
                if vm.network_profile and vm.network_profile.network_interfaces:
                    for nic in vm.network_profile.network_interfaces:
                        relationships.append({
                            "target_id": nic.id,
                            "type": "ATTACHED_TO"
                        })
                        
                # VM -> Resource Group
                if vm.id:
                    rg = vm.id.split('/')[4]
                    relationships.append({
                        "target_id": f"/subscriptions/{self.subscription_id}/resourceGroups/{rg}",
                        "type": "BELONGS_TO"
                    })

                env = self._build_envelope(
                    asset_id=vm.id,
                    resource_type="azure_vm",
                    region=vm.location,
                    name=vm.name,
                    configuration=vm.as_dict() if hasattr(vm, 'as_dict') else {},
                    relationships=relationships
                )
                envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting VMs: {e}")

        return envelopes

class NICCollector(BaseAzureCollector):
    def __init__(self, credential, subscription_id: str):
        super().__init__(credential, subscription_id)
        self.collector_name = "azure_nic"
        try:
            from azure.mgmt.network import NetworkManagementClient
            self.client = NetworkManagementClient(self.credential, self.subscription_id)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            logger.warning("Azure SDK not installed. Skipping NIC collection.")
            return []

        envelopes = []
        try:
            nics = self.client.network_interfaces.list_all()
            for nic in nics:
                relationships = []
                
                # NIC -> Subnet
                if nic.ip_configurations:
                    for ip_config in nic.ip_configurations:
                        if ip_config.subnet:
                            relationships.append({
                                "target_id": ip_config.subnet.id,
                                "type": "LOCATED_IN"
                            })
                
                # NIC -> NSG
                if nic.network_security_group:
                    relationships.append({
                        "target_id": nic.network_security_group.id,
                        "type": "PROTECTED_BY"
                    })
                
                env = self._build_envelope(
                    asset_id=nic.id,
                    resource_type="azure_nic",
                    region=nic.location,
                    name=nic.name,
                    configuration=nic.as_dict() if hasattr(nic, 'as_dict') else {},
                    relationships=relationships
                )
                envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting NICs: {e}")

        return envelopes
