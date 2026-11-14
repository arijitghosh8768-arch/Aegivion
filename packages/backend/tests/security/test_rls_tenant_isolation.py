import os
import uuid
import pytest
from sqlalchemy import text
from app.database.session import SessionLocal, set_session_tenant
from app.models.organization import Organization
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.cloud import CloudAccount

def test_rls_tenant_isolation_select_and_insert():
    """
    Test PostgreSQL Row-Level Security:
    1. Create Org A and Org B with associated CloudAccounts and Findings.
    2. Switch session context to Org A using set_session_tenant().
    3. Querying findings should ONLY return Org A's findings. Org B findings must be invisible.
    4. Attempting to insert an Org B finding while in Org A's context must be rejected by RLS.
    """
    db = SessionLocal()

    org_a_id = uuid.uuid4()
    org_a_slug = f"org-a-{uuid.uuid4().hex[:8]}"
    org_a = Organization(id=org_a_id, name="Tenant Org A", slug=org_a_slug)

    org_b_id = uuid.uuid4()
    org_b_slug = f"org-b-{uuid.uuid4().hex[:8]}"
    org_b = Organization(id=org_b_id, name="Tenant Org B", slug=org_b_slug)

    db.add_all([org_a, org_b])
    db.commit()

    finding_a_id = uuid.uuid4()
    finding_b_id = uuid.uuid4()

    # Create findings for Org A and Org B in system / bypass mode
    set_session_tenant(db, None)

    finding_a = Finding(
        id=finding_a_id,
        organization_id=org_a_id,
        title="Org A Open S3 Bucket",
        description="Public access granted in Org A",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        resource_id="arn:aws:s3:::org-a-data",
        resource_name="org-a-data",
        resource_type="s3_bucket",
        cloud_provider="aws",
        rule_id="RULE-S3-001",
        rule_name="S3 Public Access"
    )

    finding_b = Finding(
        id=finding_b_id,
        organization_id=org_b_id,
        title="Org B SSH Exposed",
        description="Port 22 open in Org B",
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        resource_id="arn:aws:ec2:::instance/i-org-b-01",
        resource_name="i-org-b-01",
        resource_type="ec2_instance",
        cloud_provider="aws",
        rule_id="RULE-EC2-001",
        rule_name="EC2 SSH Public"
    )

    db.add_all([finding_a, finding_b])
    db.commit()

    # Expire and detach so expired attribute loader doesn't attempt to reload across tenants
    db.expunge_all()

    try:
        # --- TEST 1: Tenant Org A Context ---
        set_session_tenant(db, str(org_a_id))

        # Query findings via direct SQL
        res = db.execute(
            text("SELECT id, organization_id, title FROM findings WHERE id IN (:fa, :fb);"),
            {"fa": str(finding_a_id), "fb": str(finding_b_id)}
        ).fetchall()
        visible_finding_ids = [r[0] for r in res]
        visible_org_ids = {r[1] for r in res}

        # Assert Org A sees its own finding, but Org B finding is completely hidden by RLS
        assert finding_a_id in visible_finding_ids
        assert finding_b_id not in visible_finding_ids
        assert visible_org_ids == {org_a_id}

        # Query via ORM
        orm_findings = db.query(Finding).filter(Finding.id.in_([finding_a_id, finding_b_id])).all()
        orm_finding_ids = [f.id for f in orm_findings]
        assert finding_a_id in orm_finding_ids
        assert finding_b_id not in orm_finding_ids

        # --- TEST 2: Tenant Cross-Org INSERT Protection ---
        # Attempt to insert a record belonging to Org B while in Org A's context
        illegal_finding = Finding(
            id=uuid.uuid4(),
            organization_id=org_b_id,
            title="Illegal Cross-Tenant Finding",
            description="Trying to inject finding into Org B",
            severity=FindingSeverity.LOW,
            status=FindingStatus.OPEN,
            resource_id="arn:aws:s3:::org-b-fake",
            resource_name="org-b-fake",
            resource_type="s3_bucket",
            cloud_provider="aws",
            rule_id="RULE-S3-002",
            rule_name="Illegal S3"
        )
        db.add(illegal_finding)

        with pytest.raises(Exception) as exc_info:
            db.commit()

        # Confirm the failure is due to RLS policy violation check
        err_str = str(exc_info.value).lower()
        assert "row-level security" in err_str or "policy" in err_str or "check" in err_str
        db.rollback()

        # --- TEST 3: Tenant Org B Context ---
        set_session_tenant(db, str(org_b_id))
        res_b = db.execute(
            text("SELECT id, organization_id, title FROM findings WHERE id IN (:fa, :fb);"),
            {"fa": str(finding_a_id), "fb": str(finding_b_id)}
        ).fetchall()
        visible_b_ids = [r[0] for r in res_b]

        assert finding_b_id in visible_b_ids
        assert finding_a_id not in visible_b_ids

    finally:
        # Reset to bypass mode for clean teardown
        set_session_tenant(db, None)
        db.execute(text("DELETE FROM findings WHERE id IN (:fa, :fb)"), {"fa": str(finding_a_id), "fb": str(finding_b_id)})
        db.execute(text("DELETE FROM organizations WHERE id IN (:oa, :ob)"), {"oa": str(org_a_id), "ob": str(org_b_id)})
        db.commit()
        db.close()

def test_rls_cloud_accounts_isolation():
    """Verify cloud_accounts table respects RLS."""
    db = SessionLocal()

    org_a_id = uuid.uuid4()
    org_a_slug = f"org-cloud-a-{uuid.uuid4().hex[:8]}"
    org_a = Organization(id=org_a_id, name="Cloud Org A", slug=org_a_slug)

    org_b_id = uuid.uuid4()
    org_b_slug = f"org-cloud-b-{uuid.uuid4().hex[:8]}"
    org_b = Organization(id=org_b_id, name="Cloud Org B", slug=org_b_slug)

    db.add_all([org_a, org_b])
    db.commit()

    acc_a_id = uuid.uuid4()
    acc_b_id = uuid.uuid4()

    set_session_tenant(db, None)

    acc_a = CloudAccount(
        id=acc_a_id,
        name="Org A AWS Account",
        provider="AWS",
        organization_id=org_a_id
    )
    acc_b = CloudAccount(
        id=acc_b_id,
        name="Org B AWS Account",
        provider="AWS",
        organization_id=org_b_id
    )
    db.add_all([acc_a, acc_b])
    db.commit()

    db.expunge_all()

    try:
        set_session_tenant(db, str(org_a_id))
        res = db.execute(
            text("SELECT id, organization_id FROM cloud_accounts WHERE id IN (:aa, :ab);"),
            {"aa": str(acc_a_id), "ab": str(acc_b_id)}
        ).fetchall()
        acc_ids = [r[0] for r in res]

        assert acc_a_id in acc_ids
        assert acc_b_id not in acc_ids

    finally:
        set_session_tenant(db, None)
        db.execute(text("DELETE FROM cloud_accounts WHERE id IN (:aa, :ab)"), {"aa": str(acc_a_id), "ab": str(acc_b_id)})
        db.execute(text("DELETE FROM organizations WHERE id IN (:oa, :ob)"), {"oa": str(org_a_id), "ob": str(org_b_id)})
        db.commit()
        db.close()
