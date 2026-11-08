from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass
import uuid
import yaml
import glob
import os

from app.database import SessionLocal
from app.models.finding import Finding
from security.engine.executor import RuleExecutor
from security.engine.risk_engine import ContextualRiskEngine
from security.engine.mitre import MitreService

@dataclass
class PipelineResult:
    scan_id: str
    assets_processed: int
    findings_generated: int
    findings_updated: int
    errors: List[str]
    duration_ms: int

class DetectionPipeline:
    """Complete detection pipeline from assets to findings with PostgreSQL ORM persistence and tenant isolation"""
    
    def __init__(self, db=None):
        self.rule_executor = None
        self.risk_engine = ContextualRiskEngine()
        self.mitre_service = MitreService()
        self.db = db or SessionLocal()
        self._owns_db = db is None

    def __del__(self):
        if getattr(self, '_owns_db', False) and hasattr(self, 'db') and self.db:
            try:
                self.db.close()
            except Exception:
                pass
    
    async def process_assets(self, scan_id: str, assets: List[Dict], organization_id: Optional[str] = None) -> PipelineResult:
        """Process all assets through the detection pipeline and persist findings to PostgreSQL"""
        start_time = datetime.now(timezone.utc)
        errors = []
        findings_count = 0
        updated_count = 0
        
        try:
            # 1. Load rules
            rules = self._load_rules()
            self.rule_executor = RuleExecutor(rules)
            
            # Resolve organization_id from param or first asset if available
            org_id = organization_id
            if not org_id and assets and 'organization_id' in assets[0]:
                org_id = str(assets[0]['organization_id'])
            
            # 2. Process each asset
            for asset in assets:
                try:
                    asset_id = asset.get('asset_id') or asset.get('resource_id')
                    if not asset_id:
                        continue

                    asset_org_id = asset.get('organization_id') or org_id
                    if not asset_org_id:
                        continue

                    # Execute rules
                    findings = self.rule_executor.execute(asset)
                    
                    for finding in findings:
                        rule_id = finding.get('rule_id')
                        
                        # Calculate risk score
                        risk_score = self.risk_engine.calculate_risk_score(
                            finding,
                            asset,
                            self._get_context(asset)
                        )
                        score_val = getattr(risk_score, 'score', 50)
                        
                        # Cryptographic SHA-256 Fingerprint (org_id + rule_id + resource_id)
                        import hashlib
                        raw_fingerprint = f"{str(asset_org_id)}:{str(rule_id)}:{str(asset_id)}"
                        fingerprint = hashlib.sha256(raw_fingerprint.encode("utf-8")).hexdigest()

                        # MITRE ATT&CK Enrichment
                        mitre_mappings = self.mitre_service.get_mappings_for_finding({"rule_id": rule_id})
                        evidence_data = finding.get('evidence', {}) or {}
                        if mitre_mappings:
                            evidence_data["mitre_attack"] = [m.to_dict() for m in mitre_mappings]
                            evidence_data["mitre_techniques"] = [m.technique_id for m in mitre_mappings]

                        # Deduplication via Fingerprint within Organization
                        existing = self.db.query(Finding).filter_by(
                            organization_id=asset_org_id,
                            fingerprint=fingerprint
                        ).first()
                        
                        now_utc = datetime.now(timezone.utc)
                        if existing:
                            # Update existing finding and increment occurrence
                            existing.occurrence_count = (existing.occurrence_count or 1) + 1
                            existing.last_seen = now_utc
                            existing.risk_score = score_val
                            existing.severity = (finding.get('severity') or existing.severity).lower()
                            
                            # Merge evidence preserving MITRE data
                            current_ev = existing.evidence or {}
                            current_ev.update(evidence_data)
                            existing.evidence = current_ev
                            
                            existing.description = finding.get('description') or existing.description
                            existing.updated_at = now_utc

                            # Reopen finding if it was previously marked resolved
                            if existing.status in ("resolved", "RESOLVED"):
                                existing.status = "open"
                                existing.reopened_at = now_utc

                            updated_count += 1
                        else:
                            # Create new SQLAlchemy Finding model instance in PostgreSQL
                            new_finding = Finding(
                                id=uuid.uuid4(),
                                organization_id=asset_org_id,
                                title=finding.get('title') or f"Security Finding for {rule_id}",
                                description=finding.get('description', ''),
                                severity=(finding.get('severity') or 'medium').lower(),
                                status="open",
                                source="cspm",
                                rule_id=rule_id,
                                rule_name=finding.get('rule_name') or finding.get('title') or rule_id,
                                resource_id=asset_id,
                                resource_name=asset.get('name') or asset_id,
                                resource_type=asset.get('type') or 'unknown',
                                resource_region=asset.get('region') or 'global',
                                cloud_provider=(asset.get('provider') or 'AWS').upper(),
                                risk_score=score_val,
                                cvss_score=finding.get('cvss_score', 5.0),
                                evidence=evidence_data,
                                remediation_steps=finding.get('remediation', {}),
                                tags=asset.get('configuration', {}).get('tags', {}),
                                fingerprint=fingerprint,
                                first_seen=now_utc,
                                last_seen=now_utc,
                                occurrence_count=1
                            )
                            self.db.add(new_finding)
                            findings_count += 1
                            
                except Exception as e:
                    errors.append(f"Asset {asset.get('asset_id')}: {str(e)}")
                    continue
            
            self.db.commit()
            duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            
            return PipelineResult(
                scan_id=scan_id,
                assets_processed=len(assets),
                findings_generated=findings_count,
                findings_updated=updated_count,
                errors=errors,
                duration_ms=duration
            )
            
        except Exception as e:
            self.db.rollback()
            return PipelineResult(
                scan_id=scan_id,
                assets_processed=0,
                findings_generated=0,
                findings_updated=0,
                errors=[str(e)],
                duration_ms=0
            )
    
    def _load_rules(self) -> List[Dict]:
        """Load all rules from YAML files"""
        rules = []
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "security", "rules"))
        if not os.path.exists(base_dir):
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules"))

        rule_files = glob.glob(os.path.join(base_dir, "**", "*.yaml"), recursive=True)
        
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r', encoding="utf-8") as f:
                    docs = yaml.safe_load_all(f)
                    for r in docs:
                        if r and isinstance(r, dict) and 'id' in r:
                            rules.append(r)
            except Exception:
                continue
        return rules
    
    def _get_context(self, asset: Dict) -> Dict:
        """Get context for risk scoring"""
        tags = asset.get('configuration', {}).get('tags', {})
        return {
            'environment': tags.get('Environment', 'unknown') if isinstance(tags, dict) else 'unknown',
            'data_classification': tags.get('DataClassification', 'unknown') if isinstance(tags, dict) else 'unknown',
            'criticality': tags.get('Criticality', 'normal') if isinstance(tags, dict) else 'normal'
        }
