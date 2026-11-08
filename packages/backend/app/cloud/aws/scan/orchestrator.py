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
            
            # Correlate findings into Incidents (M3 / CorrelationEngineV2)
            incidents_count = await self._correlate_incidents(all_assets)
            
            # Sync Compliance Control Results (M4 / Compliance Sync)
            await self._sync_compliance()
            
            # Update scan job
            self._update_status(
                ScanStatus.COMPLETED,
                assets_discovered=len(all_assets),
                findings_generated=findings_count,
                collector_status=collector_status,
                error_summary=None
            )
            
        except Exception as e:
            self.db.rollback()
            error_msg = f"{type(e).__name__}: {str(e)}"
            logger.error(f"Scan failed for account {self.cloud_account_id}: {error_msg}")
            self._update_status(
                ScanStatus.FAILED,
                error_summary=error_msg[:450]
            )
    
    def _initialize_collectors(self, session) -> Dict[str, Any]:
        """Initialize all collectors with resilient AWS client configuration"""
        from app.cloud.aws.collectors.ec2 import EC2Collector
        from app.cloud.aws.collectors.s3 import S3Collector
        from app.cloud.aws.collectors.iam import IAMCollector
        from app.cloud.aws.collectors.security_groups import SecurityGroupCollector
        from app.cloud.aws.collectors.vpc import VPCCollector
        from app.cloud.aws.collectors.subnets import SubnetCollector
        from app.cloud.aws.collectors.rds import RDSCollector
        from app.cloud.aws.client import AWS_CLIENT_CONFIG

        region = getattr(self.scan_job, 'region', None) or 'ap-south-1'

        return {
            'ec2': EC2Collector(session, region),
            's3': S3Collector(session, region),
            'iam': IAMCollector(session),
            'security_groups': SecurityGroupCollector(session, region),
            'vpc': VPCCollector(session, region),
            'subnets': SubnetCollector(session, region),
            'rds': RDSCollector(session, region)
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
        """Persist normalized assets with SHA-256 incremental diff and snapshot history"""
        from app.models.cloud import (
            EC2InstanceAsset,
            S3BucketAsset,
            IAMUserAsset,
            SecurityGroupAsset
        )
        from app.models.history import AssetSnapshot
        import hashlib
        import json
        from datetime import timezone

        count = 0
        now_utc = datetime.now(timezone.utc)
        scan_id_str = str(self.scan_job.id) if self.scan_job else None

        for asset in assets:
            try:
                asset_id_str = asset.get('asset_id')
                if not asset_id_str:
                    continue

                asset_type = (asset.get('type') or '').lower()
                config = asset.get('configuration') or {}

                # Calculate deterministic SHA-256 hash of configuration
                canonical_json = json.dumps(config, sort_keys=True, default=str)
                config_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

                # 1. Check existing parent CloudAsset
                existing = self.db.query(CloudAsset).filter_by(
                    resource_id=asset_id_str,
                    account_id=self.cloud_account_id
                ).first()

                if existing:
                    # Incremental diff check: If hash is identical, skip snapshot & child updates
                    if existing.current_hash == config_hash:
                        existing.last_seen_at = now_utc
                        count += 1
                        continue

                    # Hash changed! Increment version & archive previous state in AssetSnapshot
                    latest_snapshot = self.db.query(AssetSnapshot).filter_by(
                        organization_id=self.organization_id,
                        asset_id=asset_id_str
                    ).order_by(AssetSnapshot.version_number.desc()).first()

                    next_version = (latest_snapshot.version_number + 1) if latest_snapshot else 1

                    snapshot = AssetSnapshot(
                        id=uuid.uuid4(),
                        organization_id=self.organization_id,
                        cloud_account_id=self.cloud_account_id,
                        asset_id=asset_id_str,
                        version_number=next_version,
                        configuration=config,
                        configuration_hash=config_hash,
                        scan_id=scan_id_str,
                        created_at=now_utc,
                        updated_at=now_utc
                    )
                    self.db.add(snapshot)

                    # Update parent asset with new hash & config
                    existing.metadata_json = config
                    existing.current_hash = config_hash
                    existing.last_seen_at = now_utc
                    existing.name = asset.get('name') or asset_id_str
                    existing.region = asset.get('region') or existing.region
                    parent_asset = existing
                else:
                    # New asset: create parent CloudAsset and Version 1 AssetSnapshot
                    parent_asset = CloudAsset(
                        id=uuid.uuid4(),
                        account_id=self.cloud_account_id,
                        resource_id=asset_id_str,
                        provider=asset.get('provider', 'AWS').upper(),
                        type=asset.get('type', 'UNKNOWN'),
                        region=asset.get('region'),
                        name=asset.get('name') or asset_id_str,
                        metadata_json=config,
                        current_hash=config_hash,
                        last_seen_at=now_utc
                    )
                    self.db.add(parent_asset)
                    self.db.flush()

                    snapshot = AssetSnapshot(
                        id=uuid.uuid4(),
                        organization_id=self.organization_id,
                        cloud_account_id=self.cloud_account_id,
                        asset_id=asset_id_str,
                        version_number=1,
                        configuration=config,
                        configuration_hash=config_hash,
                        scan_id=scan_id_str,
                        created_at=now_utc,
                        updated_at=now_utc
                    )
                    self.db.add(snapshot)

                # 2. Upsert specialized Child Models linked to parent_asset.id
                if asset_type in ('ec2', 'ec2_instance'):
                    child_ec2 = self.db.query(EC2InstanceAsset).filter_by(asset_id=parent_asset.id).first()
                    has_pub = bool(config.get('public_ip'))
                    sec_groups = config.get('security_groups') or []
                    if child_ec2:
                        child_ec2.instance_id = asset_id_str
                        child_ec2.state = config.get('state', 'UNKNOWN')
                        child_ec2.public_ip = config.get('public_ip')
                        child_ec2.private_ip = config.get('private_ip')
                        child_ec2.instance_type = config.get('instance_type', 'unknown')
                        child_ec2.security_groups = sec_groups
                        child_ec2.has_public_ip = has_pub
                    else:
                        self.db.add(EC2InstanceAsset(
                            id=uuid.uuid4(),
                            asset_id=parent_asset.id,
                            instance_id=asset_id_str,
                            state=config.get('state', 'UNKNOWN'),
                            public_ip=config.get('public_ip'),
                            private_ip=config.get('private_ip'),
                            instance_type=config.get('instance_type', 'unknown'),
                            security_groups=sec_groups,
                            has_public_ip=has_pub
                        ))

                elif asset_type in ('s3', 's3_bucket'):
                    child_s3 = self.db.query(S3BucketAsset).filter_by(asset_id=parent_asset.id).first()
                    bucket_name = config.get('bucket_name') or asset.get('name') or asset_id_str
                    arn = config.get('arn') or f"arn:aws:s3:::{bucket_name}"
                    is_pub = bool(config.get('is_public') or config.get('public_access'))
                    enc = bool(config.get('encryption_enabled') or config.get('encrypted'))
                    ver = bool(config.get('versioning_enabled') or config.get('versioning'))
                    if child_s3:
                        child_s3.bucket_name = bucket_name
                        child_s3.arn = arn
                        child_s3.is_public = is_pub
                        child_s3.encryption_enabled = enc
                        child_s3.versioning_enabled = ver
                    else:
                        self.db.add(S3BucketAsset(
                            id=uuid.uuid4(),
                            asset_id=parent_asset.id,
                            bucket_name=bucket_name,
                            arn=arn,
                            is_public=is_pub,
                            encryption_enabled=enc,
                            versioning_enabled=ver
                        ))

                elif asset_type in ('iam', 'iam_user'):
                    child_iam = self.db.query(IAMUserAsset).filter_by(asset_id=parent_asset.id).first()
                    username = config.get('username') or asset.get('name') or asset_id_str
                    arn = config.get('arn') or asset_id_str
                    mfa = bool(config.get('mfa_enabled', False))
                    admin = bool(config.get('is_admin', False))
                    key_age = int(config.get('access_keys_age_days') or 0)
                    if child_iam:
                        child_iam.username = username
                        child_iam.arn = arn
                        child_iam.mfa_enabled = mfa
                        child_iam.is_admin = admin
                        child_iam.access_keys_age_days = key_age
                    else:
                        self.db.add(IAMUserAsset(
                            id=uuid.uuid4(),
                            asset_id=parent_asset.id,
                            username=username,
                            arn=arn,
                            mfa_enabled=mfa,
                            is_admin=admin,
                            access_keys_age_days=key_age
                        ))

                elif asset_type in ('security_group', 'security_groups'):
                    child_sg = self.db.query(SecurityGroupAsset).filter_by(asset_id=parent_asset.id).first()
                    group_id = config.get('group_id') or asset_id_str
                    group_name = config.get('group_name') or asset.get('name') or group_id
                    vpc_id = config.get('vpc_id')
                    ingress = config.get('ingress_rules') or []
                    egress = config.get('egress_rules') or []
                    if child_sg:
                        child_sg.group_id = group_id
                        child_sg.group_name = group_name
                        child_sg.vpc_id = vpc_id
                        child_sg.ingress_rules = ingress
                        child_sg.egress_rules = egress
                    else:
                        self.db.add(SecurityGroupAsset(
                            id=uuid.uuid4(),
                            asset_id=parent_asset.id,
                            group_id=group_id,
                            group_name=group_name,
                            vpc_id=vpc_id,
                            ingress_rules=ingress,
                            egress_rules=egress
                        ))

                count += 1
            except Exception as e:
                continue
        
        self.db.commit()
        return count
    
    async def _build_relationships(self, assets: List[Dict]):
        """Build relationship graph from assets and populate AssetRelationship layer"""
        from app.models.cloud import AssetRelationship
        
        relationship_map = {}
        for asset in assets:
            asset_id = asset['asset_id']
            relationships = asset.get('relationships', [])
            
            for rel in relationships:
                target_id = rel.get('target_id')
                if target_id:
                    key = f"{asset_id}|{rel['type'].upper()}|{target_id}"
                    relationship_map[key] = {
                        'source_id': asset_id,
                        'target_id': target_id,
                        'type': rel['type'].upper(),
                        'target_type': rel.get('target_type'),
                        'evidence': rel.get('evidence') or {},
                        'confidence': rel.get('confidence') or "CONFIRMED"
                    }
        
        for key, rel in relationship_map.items():
            try:
                # 1. Standard Relationship populate
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
                
                # 2. Canonical AssetRelationship layer populate with tenant isolation
                existing_asset_rel = self.db.query(AssetRelationship).filter_by(
                    organization_id=self.organization_id,
                    cloud_account_id=self.cloud_account_id,
                    source_asset_id=rel['source_id'],
                    target_asset_id=rel['target_id'],
                    relationship_type=rel['type']
                ).first()
                
                if not existing_asset_rel:
                    new_asset_rel = AssetRelationship(
                        id=str(uuid.uuid4()),
                        organization_id=self.organization_id,
                        cloud_account_id=self.cloud_account_id,
                        source_asset_id=rel['source_id'],
                        target_asset_id=rel['target_id'],
                        relationship_type=rel['type'],
                        account_id=self.cloud_account_id[:12] if self.cloud_account_id else "123456789012",
                        region=self.scan_job.region or "ap-south-1",
                        evidence=rel['evidence'],
                        confidence=rel['confidence'],
                        first_seen_at=datetime.utcnow(),
                        last_seen_at=datetime.utcnow()
                    )
                    self.db.add(new_asset_rel)
                else:
                    existing_asset_rel.last_seen_at = datetime.utcnow()
                    existing_asset_rel.evidence = rel['evidence']
            except Exception:
                continue
        
        self.db.commit()
    
    async def _trigger_rule_engine(self, assets: List[Dict]) -> int:
        """Trigger rule engine (M2) and get findings count with proper tenant isolation"""
        try:
            from security.pipeline.detection_pipeline import DetectionPipeline
            pipeline = DetectionPipeline(db=self.db)
            result = await pipeline.process_assets(
                str(self.scan_job.id),
                assets,
                organization_id=self.organization_id
            )
            return result.findings_generated
        except Exception as e:
            logger.error(f"Error executing rule engine: {e}")
            return 0

    async def _correlate_incidents(self, assets: List[Dict]) -> int:
        """Correlate findings into Incidents (M3) and persist with cryptographic fingerprint idempotency"""
        try:
            import hashlib
            from datetime import timezone
            from app.models.finding import Finding
            from app.models.incident import Incident
            from app.models.cloud import AssetRelationship
            from security.correlation.engine_v2 import CorrelationEngineV2

            # 1. Fetch active open findings for this organization
            findings_query = self.db.query(Finding).filter(
                Finding.organization_id == self.organization_id,
                Finding.status.in_(["open", "OPEN", "reopened", "REOPENED", "in_progress", "IN_PROGRESS"])
            ).all()

            if not findings_query:
                return 0

            # Convert finding models to dictionary format expected by CorrelationEngineV2
            findings_data = []
            for f in findings_query:
                findings_data.append({
                    "id": str(f.id),
                    "finding_id": str(f.id),
                    "asset_id": f.resource_id,
                    "resource_id": f.resource_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "rule_id": f.rule_id,
                    "risk_score": f.risk_score or 50.0,
                    "created_at": f.first_seen.isoformat() if f.first_seen else datetime.now(timezone.utc).isoformat()
                })

            # 2. Fetch relationships for correlation context
            relationships_query = self.db.query(AssetRelationship).filter(
                AssetRelationship.organization_id == self.organization_id
            ).all()

            relationships_data = []
            for r in relationships_query:
                relationships_data.append({
                    "source_asset_id": r.source_asset_id,
                    "target_asset_id": r.target_asset_id,
                    "relationship_type": r.relationship_type,
                    "confidence": r.confidence
                })

            # 3. Run correlation engine
            engine = CorrelationEngineV2()
            engine.load_data(findings=findings_data, assets=assets, relationships=relationships_data)
            correlated_groups = engine.correlate()

            incidents_created_or_updated = 0
            now_utc = datetime.now(timezone.utc)

            for group in correlated_groups:
                # Process candidate incidents or strong/moderate correlations
                if not (group.incident_candidate or group.strength in ("strong", "moderate") or len(group.finding_ids) > 1):
                    continue

                # Generate deterministic correlation fingerprint: sha256(org_id + group_id)
                raw_fp = f"{str(self.organization_id)}:{str(group.group_id)}"
                fp = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()

                # Calculate composite severity and risk score for the group
                group_findings = [f for f in findings_data if f["id"] in group.finding_ids]
                max_risk = max([f.get("risk_score", 50.0) for f in group_findings], default=50.0)
                severities = [f.get("severity", "medium").lower() for f in group_findings]
                
                if "critical" in severities:
                    comp_severity = "critical"
                elif "high" in severities:
                    comp_severity = "high"
                elif "medium" in severities:
                    comp_severity = "medium"
                else:
                    comp_severity = "low"

                comp_title = f"Correlated Incident ({group.group_id}): {len(group.finding_ids)} linked security findings"
                comp_desc = f"Correlated incident involving {len(group.asset_ids)} assets ({', '.join(group.asset_ids[:3])}) with reasons: {', '.join(group.reasons)}."

                # Look for existing incident with this correlation_fingerprint in this organization
                existing_incident = self.db.query(Incident).filter(
                    Incident.organization_id == self.organization_id,
                    Incident.correlation_fingerprint == fp
                ).first()

                if existing_incident:
                    # Idempotent update
                    existing_incident.last_seen_at = now_utc
                    existing_incident.risk_score = int(max_risk)
                    existing_incident.severity = comp_severity
                    
                    # Merge finding_ids and asset_ids
                    current_findings = set(existing_incident.finding_ids or [])
                    current_findings.update(group.finding_ids)
                    existing_incident.finding_ids = sorted(list(current_findings))

                    current_assets = set(existing_incident.asset_ids or [])
                    current_assets.update(group.asset_ids)
                    existing_incident.asset_ids = sorted(list(current_assets))

                    # Update evidence
                    evidence = existing_incident.evidence or {}
                    evidence.update({
                        "correlation_reasons": group.reasons,
                        "correlation_strength": group.strength,
                        "group_id": group.group_id,
                        "updated_at": now_utc.isoformat()
                    })
                    existing_incident.evidence = evidence
                    existing_incident.updated_at = now_utc
                    incidents_created_or_updated += 1
                else:
                    # Create new Incident record
                    new_incident = Incident(
                        id=uuid.uuid4(),
                        organization_id=self.organization_id,
                        cloud_account_id=self.cloud_account_id,
                        title=comp_title,
                        description=comp_desc,
                        severity=comp_severity,
                        risk_score=int(max_risk),
                        confidence=0.90 if group.strength == "strong" else 0.80,
                        status="open",
                        first_seen_at=now_utc,
                        last_seen_at=now_utc,
                        finding_ids=group.finding_ids,
                        asset_ids=group.asset_ids,
                        evidence={
                            "correlation_reasons": group.reasons,
                            "correlation_strength": group.strength,
                            "group_id": group.group_id
                        },
                        correlation_fingerprint=fp,
                        timeline=[{
                            "timestamp": now_utc.isoformat(),
                            "title": "Incident Correlated and Opened",
                            "description": f"Created from correlated findings group {group.group_id}."
                        }],
                        notes=[]
                    )
                    self.db.add(new_incident)
                    incidents_created_or_updated += 1

            self.db.commit()
            return incidents_created_or_updated
        except Exception as e:
            logger.error(f"Error executing correlation engine: {e}")
            return 0

    async def _sync_compliance(self) -> int:
        """Sync compliance control results from findings for this organization"""
        try:
            from app.services.compliance_sync import sync_compliance_from_findings
            scan_id_str = str(self.scan_job.id) if self.scan_job else None
            return sync_compliance_from_findings(
                db=self.db,
                organization_id=str(self.organization_id),
                cloud_account_id=str(self.cloud_account_id) if self.cloud_account_id else None,
                scan_id=scan_id_str
            )
        except Exception as e:
            logger.error(f"Error syncing compliance controls: {e}")
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
        """Get AWS session for the cloud account supporting direct credentials and cross-account IAM role assumption"""
        from app.cloud.aws.client import get_aws_session
        account = self.db.query(CloudAccount).filter_by(id=self.cloud_account_id).first()
        if account:
            session = get_aws_session(
                aws_access_key_id=account.aws_access_key_id,
                aws_secret_access_key=account.aws_secret_access_key,
                aws_region=account.aws_region or "ap-south-1",
                role_arn=getattr(account, "role_arn", None),
                external_id=getattr(account, "external_id", None),
                session_name=f"AegivionScan-{str(self.cloud_account_id)[:8]}"
            )
            if session:
                return session

        return boto3.Session()
