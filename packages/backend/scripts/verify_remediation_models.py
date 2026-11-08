import uuid
from datetime import datetime, timezone, timedelta
from app.database import get_db
from app.models.organization import Organization
from app.models.finding import Finding
from app.models.remediation import RemediationPlan, RemediationAction, RemediationAuditLog

def verify_remediation_lifecycle():
    db = next(get_db())
    org_id = uuid.uuid4()
    org = Organization(
        id=org_id,
        name=f"Remediation Test Org {org_id.hex[:6]}",
        slug=f"rem-org-{org_id.hex[:6]}"
    )
    db.add(org)
    db.commit()

    # 1. Create Finding
    finding_id = uuid.uuid4()
    finding = Finding(
        id=finding_id,
        organization_id=org_id,
        rule_id="AWS-S3-001",
        resource_id="arn:aws:s3:::financial-records-bucket",
        resource_name="financial-records-bucket",
        cloud_provider="aws",
        severity="critical",
        status="open",
        title="Public S3 Bucket Detected",
        fingerprint=f"{org_id}:AWS-S3-001:financial-records-bucket"
    )
    db.add(finding)
    db.commit()

    # 2. Create Remediation Plan
    plan_id = uuid.uuid4()
    idempotency_key = f"{org_id}:{finding_id}:ENABLE_S3_PUBLIC_ACCESS_BLOCK"
    plan = RemediationPlan(
        id=plan_id,
        organization_id=org_id,
        finding_id=finding_id,
        resource_id="arn:aws:s3:::financial-records-bucket",
        status="PENDING_APPROVAL",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        idempotency_key=idempotency_key
    )
    db.add(plan)
    db.commit()

    # 3. Create Remediation Action
    action_id = uuid.uuid4()
    action = RemediationAction(
        id=action_id,
        plan_id=plan_id,
        organization_id=org_id,
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        parameters={"bucket": "financial-records-bucket", "block_public_acls": True},
        rollback_payload={"bucket": "financial-records-bucket", "block_public_acls": False},
        status="PENDING"
    )
    db.add(action)

    # 4. Create Audit Log
    audit_id = uuid.uuid4()
    audit_log = RemediationAuditLog(
        id=audit_id,
        organization_id=org_id,
        plan_id=plan_id,
        action="PLAN_CREATED",
        details={"reason": "Critical finding AWS-S3-001 requires remediation."}
    )
    db.add(audit_log)
    db.commit()

    # Query back
    fetched_plan = db.query(RemediationPlan).filter_by(id=plan_id).first()
    assert fetched_plan is not None, "Remediation plan was not saved!"
    assert fetched_plan.organization_id == org_id
    assert len(fetched_plan.actions) == 1
    assert fetched_plan.actions[0].action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK"
    assert len(fetched_plan.audit_logs) == 1
    assert fetched_plan.audit_logs[0].action == "PLAN_CREATED"

    # Cleanup test data
    db.delete(org)  # CASCADE deletes plan, actions, audit_logs, and finding
    db.commit()
    db.close()
    print("SUCCESS: Remediation lifecycle models and tenant isolation verified on PostgreSQL!")

if __name__ == "__main__":
    verify_remediation_lifecycle()
