import logging
from typing import Dict, Any, List
from .base import BaseAzureCollector

logger = logging.getLogger(__name__)

class ManagedIdentityCollector(BaseAzureCollector):
    def __init__(self, credential, subscription_id: str):
        super().__init__(credential, subscription_id)
        self.collector_name = "azure_managed_identity"
        try:
            # We mock the identity client import
            from azure.mgmt.msi import ManagedServiceIdentityClient
            self.client = ManagedServiceIdentityClient(self.credential, self.subscription_id)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            identities = self.client.user_assigned_identities.list_by_subscription()
            for ident in identities:
                env = self._build_envelope(
                    asset_id=ident.id,
                    resource_type="azure_managed_identity",
                    region=ident.location,
                    name=ident.name,
                    configuration=ident.as_dict() if hasattr(ident, 'as_dict') else {},
                    relationships=[]
                )
                envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting Managed Identities: {e}")

        return envelopes

class RoleAssignmentCollector(BaseAzureCollector):
    def __init__(self, credential, subscription_id: str):
        super().__init__(credential, subscription_id)
        self.collector_name = "azure_role_assignment"
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient
            self.client = AuthorizationManagementClient(self.credential, self.subscription_id)
        except ImportError:
            self.client = None

    async def collect(self) -> List[Dict[str, Any]]:
        if not self.client:
            return []

        envelopes = []
        try:
            assignments = self.client.role_assignments.list_for_subscription()
            for asn in assignments:
                relationships = [
                    {
                        "target_id": asn.scope,
                        "type": "CAN_ACCESS"
                    },
                    {
                        "target_id": asn.principal_id, # Can be identity, user, group
                        "type": "ATTACHED_TO"
                    }
                ]
                env = self._build_envelope(
                    asset_id=asn.id,
                    resource_type="azure_role_assignment",
                    region="global",
                    name=asn.name,
                    configuration=asn.as_dict() if hasattr(asn, 'as_dict') else {},
                    relationships=relationships
                )
                envelopes.append(env.model_dump())
        except Exception as e:
            logger.error(f"Error collecting Role Assignments: {e}")

        return envelopes
