import os
import time
import logging
from typing import Dict, Any, List
from datetime import datetime

# AWS Boto3 SDK
import boto3

# AEGIVION Supabase & Mappings
from app.database.supabase_client import supabase
from app.cloud.aws.collectors.ec2 import EC2Collector
from app.cloud.aws.collectors.s3 import S3Collector
from app.cloud.aws.collectors.iam import IAMCollector
# Assume others exist or will be added

logger = logging.getLogger(__name__)

class AWSCloudSync:
    """
    Real-Data AWS Sync Pipeline.
    Connects to AWS, extracts resources, normalizes them, and persists to Supabase.
    """
    
    def __init__(self, organization_id: str, cloud_account_id: str, aws_access_key: str, aws_secret_key: str, default_region: str = "ap-south-1"):
        self.organization_id = organization_id
        self.cloud_account_id = cloud_account_id
        self.region = default_region
        
        # Create Boto3 Session (Securely initialized with scoped credentials)
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=self.region
        )
        
        self.collectors = [
            EC2Collector(self.session, self.region),
            S3Collector(self.session, self.region),
            IAMCollector(self.session, self.region)
        ]

    def run_sync(self):
        """Executes the full collection and storage lifecycle."""
        logger.info(f"Starting AWS sync for account {self.cloud_account_id}")
        
        # Mark sync started
        supabase.table("cloud_accounts").update({
            "status": "SYNCING",
            "last_sync_at": datetime.utcnow().isoformat()
        }).eq("id", self.cloud_account_id).execute()
        
        try:
            total_assets = 0
            for collector in self.collectors:
                import asyncio
                import inspect
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
                rtype = getattr(collector, 'resource_type', collector.__class__.__name__.replace('Collector', '').lower())
                normalized_assets = [self._normalize(r, rtype) for r in raw_resources]
                self._store_in_supabase(normalized_assets)
                total_assets += len(normalized_assets)
                
            # Mark sync success
            supabase.table("cloud_accounts").update({
                "status": "HEALTHY",
                "last_success_at": datetime.utcnow().isoformat()
            }).eq("id", self.cloud_account_id).execute()
            
            logger.info(f"AWS sync complete. Stored {total_assets} assets.")
            return True
            
        except Exception as e:
            logger.error(f"AWS sync failed: {str(e)}")
            supabase.table("cloud_accounts").update({
                "status": "FAILED",
                "last_error": str(e)
            }).eq("id", self.cloud_account_id).execute()
            return False

    def _normalize(self, raw_resource: Dict[str, Any], resource_type: str) -> Dict[str, Any]:
        """Converts AWS-specific shapes into the standard Aegivion CloudAsset schema."""
        
        # Extract generic identifiers (Implementation depends on the raw resource shape)
        # Boto3 resources typically use IDs like 'InstanceId', 'BucketName', 'RoleName'
        provider_id = (
            raw_resource.get('InstanceId') or 
            raw_resource.get('BucketName') or 
            raw_resource.get('RoleName') or 
            raw_resource.get('Id') or 
            f"unknown-{int(time.time())}"
        )
        
        name = raw_resource.get('BucketName') or raw_resource.get('RoleName')
        if not name and 'Tags' in raw_resource:
            name = next((t['Value'] for t in raw_resource.get('Tags', []) if t['Key'] == 'Name'), provider_id)
            
        status = raw_resource.get('State', {}).get('Name', 'ACTIVE')
        
        return {
            "organization_id": self.organization_id,
            "cloud_account_id": self.cloud_account_id,
            "provider": "aws",
            "provider_resource_id": provider_id,
            "resource_type": f"aws_{resource_type.lower()}",
            "name": name or provider_id,
            "location": self.region,
            "status": status.upper(),
            "configuration": raw_resource,
            "tags": {t['Key']: t['Value'] for t in raw_resource.get('Tags', [])} if isinstance(raw_resource.get('Tags'), list) else {},
            "provider_metadata": {"raw": True}
        }

    def _store_in_supabase(self, assets: List[Dict[str, Any]]):
        """Upserts the normalized assets into Supabase."""
        for asset in assets:
            # Check if asset exists
            existing = supabase.table("cloud_assets").select("id, version, configuration").eq(
                "provider_resource_id", asset["provider_resource_id"]
            ).eq("organization_id", self.organization_id).execute()
            
            if existing.data:
                # Update existing
                current = existing.data[0]
                new_version = current["version"]
                
                # Simple change detection
                if str(current["configuration"]) != str(asset["configuration"]):
                    new_version += 1
                    # Store historical version
                    supabase.table("asset_versions").insert({
                        "asset_id": current["id"],
                        "version": current["version"],
                        "configuration": current["configuration"]
                    }).execute()
                
                supabase.table("cloud_assets").update({
                    **asset,
                    "last_seen": datetime.utcnow().isoformat(),
                    "version": new_version
                }).eq("id", current["id"]).execute()
            else:
                # Insert new
                supabase.table("cloud_assets").insert(asset).execute()
