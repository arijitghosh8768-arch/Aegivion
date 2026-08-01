from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
import boto3
import uuid
from app.database import SessionLocal
from app.models.cloud import ScanJob, ScanStatus, CloudAsset, Relationship, CloudAccount

class ScanOrchestrator:
    """Unified AWS scan orchestrator with background processing"""
    
    def __init__(self, cloud_account_id: str, organization_id: str):
        self.cloud_account_id = cloud_account_id
        self.organization_id = organization_id
        self.scan_job = None
        self.db = SessionLocal()
    
    async def start_scan(self) -> Dict[str, Any]:
        """Start a new scan job"""
        
        # Create scan job record
        self.scan_job = ScanJob(
            id=uuid.uuid4(),
            cloud_account_id=self.cloud_account_id,
            organization_id=self.organization_id,
            status=ScanStatus.QUEUED,
            started_at=datetime.utcnow()
        )
        self.db.add(self.scan_job)
        self.db.commit()
        
        # Start background task
        asyncio.create_task(self._run_scan())
        
        return {
            "scan_id": str(self.scan_job.id),
            "status": "queued",
            "message": "Scan job created successfully"
        }
    
    async def _run_scan(self):
        """Execute the scan in background"""
        try:
            # Update status
            self._update_status(ScanStatus.RUNNING)
            
            # Get AWS session
            session = await self._get_aws_session()
            
            # Initialize collectors
            collectors = self._initialize_collectors(session)
            
            # Run all collectors in parallel
            results = await self._run_collectors(collectors)
            
            # Process results
            all_assets = []
            collector_status = {}
            
            for name, result in results.items():
                if result['success']:
                    all_assets.extend(result['assets'])
                    collector_status[name] = 'completed'
                else:
                    collector_status[name] = 'failed'
            
            # Normalize and persist assets
            await self._persist_assets(all_assets)
            
            # Build relationships
            await self._build_relationships(all_assets)
            
            # Trigger rule engine (call M2 / DetectionPipeline)
            findings_count = await self._trigger_rule_engine(all_assets)
            
            # Update scan job
            self._update_status(
                ScanStatus.COMPLETED,
                assets_discovered=len(all_assets),
                findings_generated=findings_count,
                collector_status=collector_status
            )
            
        except Exception as e:
            self.db.rollback()
            self._update_status(
                ScanStatus.FAILED,
                error_summary=str(e)[:450]
            )
    
    def _initialize_collectors(self, session) -> Dict[str, Any]:
        """Initialize all collectors"""
        from app.cloud.aws.collectors.ec2 import EC2Collector
        from app.cloud.aws.collectors.s3 import S3Collector
        from app.cloud.aws.collectors.iam import IAMCollector
        from app.cloud.aws.collectors.security_groups import SecurityGroupCollector
        from app.cloud.aws.collectors.vpc import VPCCollector
        from app.cloud.aws.collectors.subnets import SubnetCollector
        
        region = self.scan_job.region or 'ap-south-1'
        
        return {
            'ec2': EC2Collector(session, region),
            's3': S3Collector(session, region),
            'iam': IAMCollector(session),
            'security_groups': SecurityGroupCollector(session, region),
            'vpc': VPCCollector(session, region),
            'subnets': SubnetCollector(session, region)
        }
    
    async def _run_collectors(self, collectors: Dict) -> Dict[str, Any]:
        """Run all collectors in parallel"""
        results = {}
        for name, collector in collectors.items():
            try:
                assets = await collector.collect()
                results[name] = {
                    'success': True,
                    'assets': assets,
                    'count': len(assets)
                }
            except Exception as e:
                results[name] = {
                    'success': False,
                    'error': str(e),
                    'assets': []
                }
        return results
    
    async def _persist_assets(self, assets: List[Dict]) -> int:
        """Persist normalized assets to database"""
        count = 0
        
        for asset in assets:
            try:
                # Check if asset exists
                existing = self.db.query(CloudAsset).filter_by(
                    resource_id=asset['asset_id'],
                    account_id=self.cloud_account_id
                ).first()
                
                if existing:
                    existing.metadata_json = asset['configuration']
                    existing.name = asset.get('name') or asset['asset_id']
                else:
                    new_asset = CloudAsset(
                        id=uuid.uuid4(),
                        account_id=self.cloud_account_id,
                        resource_id=asset['asset_id'],
                        provider=asset['provider'].upper(),
                        type=asset['type'],
                        region=asset.get('region'),
                        name=asset.get('name') or asset['asset_id'],
                        metadata_json=asset['configuration']
                    )
                    self.db.add(new_asset)
                count += 1
            except Exception:
                continue
        
        self.db.commit()
        return count
    
    async def _build_relationships(self, assets: List[Dict]):
        """Build relationship graph from assets"""
        relationship_map = {}
        
        for asset in assets:
            asset_id = asset['asset_id']
            relationships = asset.get('relationships', [])
            
            for rel in relationships:
                target_id = rel.get('target_id')
                if target_id:
                    key = f"{asset_id}|{rel['type']}|{target_id}"
                    relationship_map[key] = {
                        'source_id': asset_id,
                        'target_id': target_id,
                        'type': rel['type'],
                        'target_type': rel.get('target_type')
                    }
        
        for rel in relationship_map.values():
            try:
                existing = self.db.query(Relationship).filter_by(
                    source_id=rel['source_id'],
                    target_id=rel['target_id'],
                    type=rel['type']
                ).first()
                
                if not existing:
                    new_rel = Relationship(
                        id=uuid.uuid4(),
                        source_id=rel['source_id'],
                        target_id=rel['target_id'],
                        type=rel['type'],
                        target_type=rel.get('target_type')
                    )
                    self.db.add(new_rel)
            except Exception:
                continue
        
        self.db.commit()
    
    async def _trigger_rule_engine(self, assets: List[Dict]) -> int:
        """Trigger rule engine (M2) and get findings count"""
        try:
            from security.pipeline.detection_pipeline import DetectionPipeline
            pipeline = DetectionPipeline()
            result = await pipeline.process_assets(str(self.scan_job.id), assets)
            return result.findings_generated
        except Exception:
            return 0
    
    def _update_status(self, status: ScanStatus, **kwargs):
        """Update scan job status"""
        if self.scan_job:
            job_id = self.scan_job.id
            db_job = self.db.query(ScanJob).filter_by(id=job_id).first()
            if db_job:
                self.scan_job = db_job
            self.scan_job.status = status
            if status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
                self.scan_job.completed_at = datetime.utcnow()
            
            for key, value in kwargs.items():
                setattr(self.scan_job, key, value)
            
            self.db.commit()
    
    async def _get_aws_session(self):
        """Get AWS session for the cloud account"""
        account = self.db.query(CloudAccount).filter_by(id=self.cloud_account_id).first()
        if account and account.aws_access_key_id and account.aws_secret_access_key:
            return boto3.Session(
                aws_access_key_id=account.aws_access_key_id,
                aws_secret_access_key=account.aws_secret_access_key,
                region_name=account.aws_region or "ap-south-1"
            )
        return boto3.Session()
