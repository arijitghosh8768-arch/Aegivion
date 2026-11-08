import os
import yaml
import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.compliance import ComplianceControlResult, ComplianceStatus
from app.models.finding import Finding

logger = logging.getLogger(__name__)

DEFAULT_MAPPINGS_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "security", "rules", "compliance_mappings.yaml")
)

def load_compliance_mappings(filepath: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Load rule_id -> compliance control definitions from YAML"""
    path = filepath or DEFAULT_MAPPINGS_FILE
    if not os.path.exists(path):
        # Fallback relative search
        alt_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "compliance_mappings.yaml"))
        if os.path.exists(alt_path):
            path = alt_path
        else:
            logger.warning(f"Compliance mappings file not found at {path}")
            return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data.get("mappings", {})
    except Exception as e:
        logger.error(f"Failed to load compliance mappings from {path}: {e}")
        return {}

def sync_compliance_from_findings(
    db: Session,
    organization_id: str,
    cloud_account_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    mappings_file: Optional[str] = None
) -> int:
    """
    Sync compliance controls from active findings for an organization.
    - Each mapped control is evaluated against current open findings.
    - If any finding matching the control is OPEN, status is FAIL.
    - If all matching findings are RESOLVED (or no findings exist), status is PASS.
    - Upserts records into the PostgreSQL compliance_results table.
    """
    mappings = load_compliance_mappings(mappings_file)
    if not mappings:
        return 0

    now_utc = datetime.now(timezone.utc)
    updated_or_created = 0

    # Group mappings by framework_id and control_code
    # A single control_code may be triggered by multiple rule_ids
    control_to_rules: Dict[tuple, Dict[str, Any]] = {}
    for rule_id, meta in mappings.items():
        framework_id = meta.get("framework_id", "CIS_AWS_v3")
        control_code = meta.get("control_code")
        if not control_code:
            continue
        key = (framework_id, control_code)
        if key not in control_to_rules:
            control_to_rules[key] = {
                "framework_id": framework_id,
                "control_code": control_code,
                "title": meta.get("title", f"Compliance Control {control_code}"),
                "description": meta.get("description", ""),
                "category": meta.get("category", "General"),
                "severity": meta.get("severity", "high"),
                "rule_ids": []
            }
        control_to_rules[key]["rule_ids"].append(rule_id)

    # For each control, check findings in DB
    for (framework_id, control_code), ctrl_info in control_to_rules.items():
        rule_ids = ctrl_info["rule_ids"]

        # Fetch findings for these rules in this organization
        findings = db.query(Finding).filter(
            Finding.organization_id == organization_id,
            Finding.rule_id.in_(rule_ids)
        ).all()

        open_findings = [
            f for f in findings
            if str(f.status).lower() in ("open", "reopened", "in_progress")
        ]

        if open_findings:
            new_status = ComplianceStatus.FAIL.value
            affected_resources = list(set([f.resource_id for f in open_findings]))
            finding_refs = [str(f.id) for f in open_findings]
            evidence_refs = [f.fingerprint for f in open_findings if f.fingerprint]
        else:
            new_status = ComplianceStatus.PASS.value
            affected_resources = []
            finding_refs = []
            evidence_refs = []

        # Upsert in PostgreSQL compliance_results
        existing = db.query(ComplianceControlResult).filter(
            ComplianceControlResult.organization_id == organization_id,
            ComplianceControlResult.control_code == control_code,
            ComplianceControlResult.framework_id == framework_id
        ).first()

        if existing:
            existing.status = new_status
            existing.affected_resources = affected_resources
            existing.finding_refs = finding_refs
            existing.evidence_refs = evidence_refs
            existing.assessed_at = now_utc
            existing.scan_id = scan_id or existing.scan_id
            existing.updated_at = now_utc
            if cloud_account_id:
                existing.cloud_account_id = cloud_account_id
            updated_or_created += 1
        else:
            new_record = ComplianceControlResult(
                id=uuid.uuid4(),
                organization_id=organization_id,
                cloud_account_id=cloud_account_id,
                control_code=control_code,
                framework_id=framework_id,
                title=ctrl_info["title"],
                description=ctrl_info["description"],
                category=ctrl_info["category"],
                severity=ctrl_info["severity"],
                status=new_status,
                affected_resources=affected_resources,
                evidence_refs=evidence_refs,
                finding_refs=finding_refs,
                assessed_at=now_utc,
                scan_id=scan_id
            )
            db.add(new_record)
            updated_or_created += 1

    db.commit()
    return updated_or_created

