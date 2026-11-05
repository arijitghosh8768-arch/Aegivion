import time
import json
import logging
import asyncio
import inspect
from typing import Dict, Any, List
from datetime import datetime, timezone
from app.database.supabase_client import supabase
from app.repositories.twin_persistence_repository import TwinPersistenceRepository

from app.cloud.gcp.collectors.compute import InstanceCollector
from app.cloud.gcp.collectors.network import NetworkCollector, SubnetworkCollector, FirewallCollector
from app.cloud.gcp.collectors.iam import ServiceAccountCollector, IAMPolicyCollector
from app.cloud.gcp.collectors.storage import StorageBucketCollector
from app.cloud.gcp.collectors.project import ProjectCollector

logger = logging.getLogger(__name__)

class GCPCloudSync:
    """
    Real-Data GCP Sync Pipeline.
    Connects to Google Cloud API, extracts resources, normalizes them,
    and persists to Supabase via Digital Twin.
    """

    def __init__(self, organization_id: str, cloud_account_id: str, project_id: str, service_account_json: str):
        self.organization_id = organization_id
        self.cloud_account_id = cloud_account_id
        self.project_id = project_id
        self.service_account_json = service_account_json

        try:
            from google.oauth2 import service_account
            self.credentials = service_account.Credentials.from_service_account_info(json.loads(service_account_json))
        except ImportError:
            self.credentials = None

        self.collectors = [
            ProjectCollector(self.credentials, self.project_id),
            InstanceCollector(self.credentials, self.project_id),
            NetworkCollector(self.credentials, self.project_id),
            SubnetworkCollector(self.credentials, self.project_id),
            FirewallCollector(self.credentials, self.project_id),
            ServiceAccountCollector(self.credentials, self.project_id),
            IAMPolicyCollector(self.credentials, self.project_id),
            StorageBucketCollector(self.credentials, self.project_id)
        ]

    def run_sync(self):
        """Executes GCP resource collection and storage."""
        logger.info(f"Starting GCP sync for account {self.cloud_account_id}")

        supabase.table("cloud_accounts").update({
            "status": "SYNCING",
            "last_sync_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", self.cloud_account_id).execute()

        try:
            total_assets = 0
            for collector in self.collectors:
                raw_resources = collector.collect()
                if inspect.isawaitable(raw_resources):
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    if loop.is_running():
                        import nest_asyncio
                        nest_asyncio.apply()
                    raw_resources = loop.run_until_complete(raw_resources)

                normalized_assets = [self._normalize(r) for r in raw_resources]
                self._store_in_supabase(normalized_assets)
                total_assets += len(normalized_assets)

            supabase.table("cloud_accounts").update({
                "status": "HEALTHY",
                "last_success_at": datetime.now(timezone.utc).isoformat()
            }).eq("id", self.cloud_account_id).execute()

            logger.info(f"GCP sync complete. Stored {total_assets} assets.")
            return True

        except Exception as e:
            logger.error(f"GCP sync failed: {str(e)}")
            supabase.table("cloud_accounts").update({
                "status": "FAILED",
                "last_error": str(e)
            }).eq("id", self.cloud_account_id).execute()
            return False

    def _normalize(self, raw_resource: Dict[str, Any]) -> Dict[str, Any]:
        """Converts GCP specific shapes into the standard Aegivion CloudAsset schema."""
        if 'asset_id' in raw_resource:
            return {
                "organization_id": self.organization_id,
                "cloud_account_id": self.cloud_account_id,
                "provider": "gcp",
                "provider_resource_id": raw_resource['asset_id'],
                "resource_type": raw_resource['resource_type'],
                "name": raw_resource.get('name', raw_resource['asset_id']),
                "location": raw_resource.get('region', 'global'),
                "status": "ACTIVE",
                "configuration": raw_resource.get('configuration', raw_resource),
                "tags": raw_resource.get('configuration', {}).get('labels', {}),
                "provider_metadata": {"raw": False, "relationships": raw_resource.get('relationships', [])}
            }

        provider_id = str(raw_resource.get('id', f"gcp-unknown-{int(time.time())}"))
        name = raw_resource.get('name', provider_id)

        return {
            "organization_id": self.organization_id,
            "cloud_account_id": self.cloud_account_id,
            "provider": "gcp",
            "provider_resource_id": provider_id,
            "resource_type": raw_resource.get('kind', 'gcp_resource'),
            "name": name,
            "location": raw_resource.get('zone', 'global'),
            "status": raw_resource.get('status', 'RUNNING').upper(),
            "configuration": raw_resource,
            "tags": raw_resource.get('labels', {}),
            "provider_metadata": {"raw": True}
        }

    def _store_in_supabase(self, assets: List[Dict[str, Any]]):
        """Upserts the normalized assets, identities, and relationships into Supabase via Digital Twin."""
        twin_repo = TwinPersistenceRepository(supabase, self.organization_id)

        for asset in assets:
            provider_resource_id = asset.get("provider_resource_id")
            if not provider_resource_id:
                continue

            existing = supabase.table("cloud_assets").select("id, version, configuration").eq(
                "provider_resource_id", provider_resource_id
            ).eq("organization_id", self.organization_id).execute()

            if existing.data:
                current = existing.data[0]
                new_version = current["version"]

                if str(current["configuration"]) != str(asset["configuration"]):
                    new_version += 1
                    supabase.table("asset_versions").insert({
                        "asset_id": current["id"],
                        "version": current["version"],
                        "configuration": current["configuration"]
                    }).execute()

                supabase.table("cloud_assets").update({
                    **asset,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "version": new_version
                }).eq("id", current["id"]).execute()
            else:
                supabase.table("cloud_assets").insert(asset).execute()

            # 2. Store Identity
            if asset.get("resource_type") == "gcp_iam_service_account":
                twin_repo.upsert_identity(self.organization_id, {
                    "account_id": self.cloud_account_id,
                    "provider": "gcp",
                    "native_id": provider_resource_id,
                    "identity_type": "SERVICE_ACCOUNT",
                    "name": asset.get("name"),
                    "status": "ACTIVE",
                    "metadata": asset.get("configuration", {})
                })

            # 3. Store Relationships
            provider_metadata = asset.get("provider_metadata", {})
            relationships = provider_metadata.get("relationships", [])
            if relationships:
                twin_repo.replace_asset_relationships(
                    self.organization_id,
                    provider_resource_id,
                    relationships
                )
