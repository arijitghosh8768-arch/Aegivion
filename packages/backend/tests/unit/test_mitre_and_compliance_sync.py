import pytest
import uuid
import hashlib
from datetime import datetime, timezone
from app.database import SessionLocal
from app.models.organization import Organization
from app.models.cloud_account import CloudAccountV2
from app.models.finding import Finding
from app.models.compliance import ComplianceControlResult, ComplianceStatus
from security.pipeline.detection_pipeline import DetectionPipeline
from app.services.compliance_sync import sync_compliance_from_findings

@pytest.mark.asyncio
async def test_mitre_enrichment_and_compliance_sync():
    """
    Verify:
    1. MITRE ATT&CK Enrichment:
       - S3 public bucket rule (AWS-S3-001) triggers finding.
       - Evidence JSONB is automatically enriched with MITRE techniques (e.g. T1530).
    2. Compliance Control Sync:
       - sync_compliance_from_findings evaluates active findings.
       - Mapped control CIS-2.1.5 ('Ensure S3 Buckets are not publicly accessible') is marked 'FAIL'.
       - Affected resources and finding references are populated in compliance_results.
    3. Remediation & Re-Sync:
       - Finding status transitions to 'resolved'.
       - Next compliance sync flips CIS-2.1.5 status to 'PASS'.
    """
    db = SessionLocal()
    org_id = uuid.uuid4()
    account_id = uuid.uuid4()
    slug = f"test-mitre-comp-{uuid.uuid4().hex[:8]}"

    try:
        # 1. Setup Organization and Account
        org = Organization(id=org_id, name="Test Mitre Compliance Org", slug=slug)
        db.add(org)
        db.commit()

        account = CloudAccountV2(
            id=account_id,
            organization_id=org_id,
            name="Test Mitre AWS Account",
            provider="AWS",
            account_id="123456789012",
            connection_status="connected",
            default_region="ap-south-1"
        )
        db.add(account)
        db.commit()

        # 2. Trigger DetectionPipeline with S3 public bucket violation
        resource_id = "arn:aws:s3:::compliance-test-bucket-99"
        assets = [
            {
                "asset_id": resource_id,
                "provider": "aws",
                "type": "s3",
                "name": "compliance-test-bucket-99",
                "region": "ap-south-1",
                "organization_id": str(org_id),
                "configuration": {
                    "bucket_name": "compliance-test-bucket-99",
                    "public_access": True,
                    "is_public": True,
                    "tags": {
                        "Environment": "Production"
                    }
                }
            }
        ]

        pipeline = DetectionPipeline(db=db)
        scan_id = str(uuid.uuid4())
        result = await pipeline.process_assets(scan_id, assets, organization_id=str(org_id))

        assert result.findings_generated >= 1

        # 3. Verify MITRE ATT&CK Enrichment in Finding evidence
        finding = db.query(Finding).filter(
            Finding.organization_id == org_id,
            Finding.resource_id == resource_id
        ).first()

        assert finding is not None
        assert finding.evidence is not None
        assert "mitre_techniques" in finding.evidence
        assert "T1530" in finding.evidence["mitre_techniques"]
        assert "mitre_attack" in finding.evidence
        assert any(m["technique_id"] == "T1530" for m in finding.evidence["mitre_attack"])

        # 4. Run Compliance Sync
        synced_count = sync_compliance_from_findings(
            db=db,
            organization_id=str(org_id),
            cloud_account_id=str(account_id),
            scan_id=scan_id
        )
        assert synced_count >= 1

        # Verify CIS-2.1.5 is FAIL because S3 bucket is public
        control_result = db.query(ComplianceControlResult).filter(
            ComplianceControlResult.organization_id == org_id,
            ComplianceControlResult.control_code == "CIS-2.1.5"
        ).first()

        assert control_result is not None
        assert control_result.status == ComplianceStatus.FAIL.value
        assert resource_id in control_result.affected_resources
        assert str(finding.id) in control_result.finding_refs

        # 5. Resolve Finding and Re-sync Compliance
        finding.status = "resolved"
        db.commit()

        synced_count_2 = sync_compliance_from_findings(
            db=db,
            organization_id=str(org_id),
            cloud_account_id=str(account_id),
            scan_id=scan_id
        )
        assert synced_count_2 >= 1

        db.expire_all()
        updated_control = db.query(ComplianceControlResult).filter(
            ComplianceControlResult.organization_id == org_id,
            ComplianceControlResult.control_code == "CIS-2.1.5"
        ).first()

        assert updated_control is not None
        assert updated_control.status == ComplianceStatus.PASS.value
        assert len(updated_control.affected_resources) == 0

    finally:
        # Cleanup
        try:
            db.query(ComplianceControlResult).filter(ComplianceControlResult.organization_id == org_id).delete()
            db.query(Finding).filter(Finding.organization_id == org_id).delete()
            db.query(CloudAccountV2).filter(CloudAccountV2.organization_id == org_id).delete()
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

