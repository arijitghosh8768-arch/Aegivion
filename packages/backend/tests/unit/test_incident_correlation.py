import pytest
import uuid
import hashlib
from datetime import datetime, timezone
from app.database import SessionLocal
from app.models.organization import Organization
from app.models.cloud_account import CloudAccountV2
from app.models.finding import Finding
from app.models.incident import Incident
from app.models.cloud import AssetRelationship
from app.cloud.aws.scan.orchestrator import ScanOrchestrator

@pytest.mark.asyncio
async def test_incident_correlation_and_idempotency():
    """
    Verify that ScanOrchestrator._correlate_incidents:
    1. Clusters correlated findings (e.g. EC2 instance with public SSH + connected Security Group).
    2. Calculates a deterministic correlation_fingerprint = sha256(org_id + ':' + group_id).
    3. Persists a new Incident record to the PostgreSQL 'incidents' table.
    4. On subsequent scan runs with the same findings/assets, updates existing incident idempotently
       (no duplicate rows created).
    """
    db = SessionLocal()
    org_id = uuid.uuid4()
    account_id = uuid.uuid4()
    slug = f"test-corr-org-{uuid.uuid4().hex[:8]}"

    try:
        # 1. Setup Organization and CloudAccount in DB
        org = Organization(id=org_id, name="Test Correlation Org", slug=slug)
        db.add(org)
        db.commit()

        account = CloudAccountV2(
            id=account_id,
            organization_id=org_id,
            name="Test Correlation AWS Account",
            provider="AWS",
            account_id="123456789012",
            connection_status="connected",
            default_region="ap-south-1"
        )
        db.add(account)
        db.commit()

        # 2. Setup mock correlated assets & relationship
        ec2_resource_id = "i-0987654321fedcba0"
        sg_resource_id = "sg-0123456789abcdef0"

        assets = [
            {
                "asset_id": ec2_resource_id,
                "name": "web-server-prod",
                "type": "ec2_instance",
                "provider": "aws",
                "region": "ap-south-1",
                "configuration": {
                    "vpc_id": "vpc-test-101",
                    "subnet_id": "subnet-test-101",
                    "tags": {"Environment": "Production", "Criticality": "high"}
                }
            },
            {
                "asset_id": sg_resource_id,
                "name": "web-secgroup-prod",
                "type": "security_group",
                "provider": "aws",
                "region": "ap-south-1",
                "configuration": {
                    "vpc_id": "vpc-test-101",
                    "tags": {"Environment": "Production"}
                }
            }
        ]

        # Add AssetRelationship between EC2 and SG
        rel = AssetRelationship(
            id=str(uuid.uuid4()),
            organization_id=org_id,
            cloud_account_id=account_id,
            source_asset_id=ec2_resource_id,
            target_asset_id=sg_resource_id,
            relationship_type="ATTACHED_SECURITY_GROUP",
            account_id="123456789012",
            region="ap-south-1",
            confidence="CONFIRMED"
        )
        db.add(rel)

        # 3. Create two correlated Findings in DB
        finding_ec2 = Finding(
            id=uuid.uuid4(),
            organization_id=org_id,
            title="Public Ingress Permitted on Production Instance",
            description="EC2 instance has direct internet ingress allowed.",
            severity="critical",
            status="open",
            source="cspm",
            rule_id="AWS-EC2-INGRESS-001",
            rule_name="AWS EC2 Public Ingress",
            resource_id=ec2_resource_id,
            resource_name="web-server-prod",
            resource_type="ec2_instance",
            cloud_provider="AWS",
            risk_score=95.0,
            cvss_score=9.0,
            fingerprint=hashlib.sha256(f"{org_id}:AWS-EC2-INGRESS-001:{ec2_resource_id}".encode()).hexdigest(),
            occurrence_count=1
        )
        finding_sg = Finding(
            id=uuid.uuid4(),
            organization_id=org_id,
            title="Security Group allows unrestricted SSH 0.0.0.0/0",
            description="Port 22 is open to the world.",
            severity="high",
            status="open",
            source="cspm",
            rule_id="AWS-SG-SSH-001",
            rule_name="AWS SG Unrestricted SSH",
            resource_id=sg_resource_id,
            resource_name="web-secgroup-prod",
            resource_type="security_group",
            cloud_provider="AWS",
            risk_score=85.0,
            cvss_score=8.0,
            fingerprint=hashlib.sha256(f"{org_id}:AWS-SG-SSH-001:{sg_resource_id}".encode()).hexdigest(),
            occurrence_count=1
        )
        db.add(finding_ec2)
        db.add(finding_sg)
        db.commit()

        # 4. Instantiate ScanOrchestrator and run _correlate_incidents (FIRST RUN)
        orchestrator = ScanOrchestrator(cloud_account_id=str(account_id), organization_id=str(org_id))
        incidents_count = await orchestrator._correlate_incidents(assets)

        assert incidents_count >= 1, f"Expected at least 1 incident created, got {incidents_count}"

        # Verify Incident in PostgreSQL
        incidents = db.query(Incident).filter(Incident.organization_id == org_id).all()
        assert len(incidents) == 1, f"Expected 1 incident in DB, found {len(incidents)}"

        inc = incidents[0]
        assert inc.severity in ("critical", "high")
        assert inc.risk_score >= 85
        assert str(finding_ec2.id) in inc.finding_ids
        assert str(finding_sg.id) in inc.finding_ids
        assert ec2_resource_id in inc.asset_ids
        assert sg_resource_id in inc.asset_ids
        assert inc.correlation_fingerprint is not None
        assert inc.status == "open"
        first_last_seen = inc.last_seen_at

        # 5. SECOND RUN (Idempotency test)
        # Calling _correlate_incidents again must update the existing record, NOT create a second incident
        incidents_count_run2 = await orchestrator._correlate_incidents(assets)
        assert incidents_count_run2 >= 1

        db.expire_all()
        incidents_after_run2 = db.query(Incident).filter(Incident.organization_id == org_id).all()
        assert len(incidents_after_run2) == 1, f"Idempotency failed! Found {len(incidents_after_run2)} incidents instead of 1."

        updated_inc = incidents_after_run2[0]
        assert updated_inc.id == inc.id
        assert updated_inc.correlation_fingerprint == inc.correlation_fingerprint
        assert updated_inc.last_seen_at >= first_last_seen

    finally:
        # Cleanup test records
        try:
            db.query(Incident).filter(Incident.organization_id == org_id).delete()
            db.query(Finding).filter(Finding.organization_id == org_id).delete()
            db.query(AssetRelationship).filter(AssetRelationship.organization_id == org_id).delete()
            db.query(CloudAccountV2).filter(CloudAccountV2.organization_id == org_id).delete()
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
