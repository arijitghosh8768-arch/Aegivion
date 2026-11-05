import logging
from typing import Dict, Any, List
from .base import BaseAzureCollector

logger = logging.getLogger(__name__)

class ResourceGroupCollector(BaseAzureCollector):
    def __init__(self, credential, subscription_id: str):
        super().__init__(credential, subscription_id)
        self.collector_name = "azure_resource_group"
        try:
            from azure.mgmt.resource import ResourceManagementClient
            self.client = ResourceManagementClient(self.credential, self.subscription_id)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            groups = self.client.resource_groups.list()
            for rg in groups:
                relationships = [{
                    "target_id": f"/subscriptions/{self.subscription_id}",
                    "type": "BELONGS_TO"
                }]
                env = self._build_envelope(
                    asset_id=rg.id,
                    resource_type="azure_resource_group",
                    region=rg.location,
                    name=rg.name,
                    configuration=rg.as_dict() if hasattr(rg, 'as_dict') else {},
                    relationships=relationships
                )
                envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting Resource Groups: {e}")

        return envelopes

class StorageAccountCollector(BaseAzureCollector):
    def __init__(self, credential, subscription_id: str):
        super().__init__(credential, subscription_id)
        self.collector_name = "azure_storage_account"
        try:
            from azure.mgmt.storage import StorageManagementClient
            self.client = StorageManagementClient(self.credential, self.subscription_id)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            accounts = self.client.storage_accounts.list()
            for acc in accounts:
                env = self._build_envelope(
                    asset_id=acc.id,
                    resource_type="azure_storage_account",
                    region=acc.location,
                    name=acc.name,
                    configuration=acc.as_dict() if hasattr(acc, 'as_dict') else {},
                    relationships=[]
                )
                envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting Storage Accounts: {e}")

        return envelopes
