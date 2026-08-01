from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass
import uuid
import yaml
import glob
import os

from app.database import SessionLocal
from security.models.finding import Finding
from security.engine.executor import RuleExecutor
from security.engine.risk_engine import ContextualRiskEngine

@dataclass
class PipelineResult:
    scan_id: str
    assets_processed: int
    findings_generated: int
    findings_updated: int
    errors: List[str]
    duration_ms: int

class DetectionPipeline:
    """Complete detection pipeline from assets to findings"""
    
    def __init__(self):
        self.rule_executor = None
        self.risk_engine = ContextualRiskEngine()
        self.db = SessionLocal()
    
    async def process_assets(self, scan_id: str, assets: List[Dict]) -> PipelineResult:
        """Process all assets through the detection pipeline"""
        start_time = datetime.utcnow()
        errors = []
        findings_count = 0
        updated_count = 0
        
        try:
            # 1. Load rules
            rules = self._load_rules()
            self.rule_executor = RuleExecutor(rules)
            
            # 2. Process each asset
            for asset in assets:
                try:
                    # Execute rules
                    findings = self.rule_executor.execute(asset)
                    
                    for finding in findings:
                        # Calculate risk score
                        risk_score = self.risk_engine.calculate_risk_score(
                            finding,
                            asset,
                            self._get_context(asset)
                        )
                        finding['risk_score'] = risk_score.score
                        finding['risk_level'] = risk_score.level.value
                        finding['risk_factors'] = risk_score.factors
                        
                        # Deduplicate (check if finding with rule_id and asset_id exists)
                        existing = self.db.query(Finding).filter_by(
                            rule_id=finding['rule_id'],
                            resource_id=finding['asset_id']
                        ).first()
                        
                        if existing:
                            # Update existing
                            existing.last_seen = datetime.utcnow()
                            existing.risk_score = finding.get('risk_score', 0)
                            existing.severity = finding['severity']
                            existing.evidence = finding.get('evidence', {})
                            existing.description = finding.get('description', '')
                            existing.updated_at = datetime.utcnow()
                            updated_count += 1
                        else:
                            # Create new
                            new_finding = Finding(
                                id=uuid.uuid4(),
                                title=finding['title'],
                                description=finding.get('description', ''),
                                severity=finding['severity'],
                                status="open",
                                rule_id=finding['rule_id'],
                                resource_id=finding['asset_id'],
                                cloud_provider=asset.get('provider', 'aws').upper(),
                                resource_type=asset.get('type', 'unknown'),
                                resource_region=asset.get('region', 'global'),
                                resource_name=asset.get('name', 'unknown'),
                                risk_score=finding.get('risk_score', 0),
                                evidence=finding.get('evidence', {}),
                                mitre_technique=finding.get('mitre_technique'),
                                mitre_tactic=finding.get('mitre_tactic'),
                                remediation=finding.get('remediation', []),
                                first_seen=datetime.utcnow(),
                                last_seen=datetime.utcnow()
                            )
                            self.db.add(new_finding)
                            findings_count += 1
                            
                except Exception as e:
                    errors.append(f"Asset {asset.get('asset_id')}: {str(e)}")
                    continue
            
            self.db.commit()
            duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            
            return PipelineResult(
                scan_id=scan_id,
                assets_processed=len(assets),
                findings_generated=findings_count,
                findings_updated=updated_count,
                errors=errors,
                duration_ms=duration
            )
            
        except Exception as e:
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
        # Support loading from security/rules/**/*.yaml
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "security", "rules"))
        rule_files = glob.glob(os.path.join(base_dir, "**", "*.yaml"), recursive=True)
        
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r') as f:
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
