"""End-to-end AWS scan validation.

This exercises the *real* pipeline that ``ScanOrchestrator`` runs:

    fake AWS discovery -> asset persistence -> relationship persistence
    -> detection (findings) -> threat correlation (incidents) -> report API

AWS itself is replaced by the deterministic ``tests.perf.fake_aws.FakeAWS``
implementation; PostgreSQL is real (the local ``DATABASE_URL``), so the tests
also validate foreign keys, tenant scoping and repeat-scan idempotency.

Run with::

    ../../.venv/Scripts/python.exe -m pytest tests/integration/test_e2e_scan_flow.py -q
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.perf.fake_aws import FakeAWS

from app.database import SessionLocal
from app.models.cloud import (
    AssetRelationship,
    CloudAccount,
    CloudAsset,
    Relationship,
    ScanJob,
    ScanStatus,
)
from app.models.cloud_account import CloudAccountV2
from app.models.finding import Finding
from app.models.history import AssetSnapshot
from app.models.incident import Incident
from app.models.organization import Organization
from app.cloud.aws.scan.orchestrator import ScanOrchestrator

# Small but structurally complete fixture set: every collector has work to do
# while the whole scan stays fast (no simulated latency here).
COLLECTOR_SIZES = dict(buckets=12, iam_users=6, iam_roles=4, iam_groups=3, iam_policies=2,
                       ec2_instances=8, security_groups=6, vpcs=3, subnets=6, rds_instances=2)



# --------------------------------------------------------------------------- helpers
def _create_tenant(db, label: str):
    """Create an organization plus the (mirrored) cloud account rows.

    ``cloud_assets.account_id`` has an FK to ``cloud_accounts_v2`` while the
    scanner resolves accounts from ``cloud_accounts``; onboarding writes both,
    so the fixture mirrors that.
    """
    org = Organization(
        id=uuid.uuid4(),
        name=f"E2E {label}",
        slug=f"e2e-{label}-{uuid.uuid4().hex[:8]}",
        subscription_plan="enterprise",
    )
    db.add(org)
    db.flush()

    account = CloudAccount(
        id=uuid.uuid4(),
        organization_id=org.id,
        name=f"E2E AWS {label}",
        provider="AWS",
        aws_region="ap-south-1",
        status="connected",
    )
    db.add(account)
    db.flush()

    db.add(CloudAccountV2(
        id=account.id,
        organization_id=org.id,
        provider="aws",
        account_id="111122223333",
        account_name=f"E2E AWS {label}",
        default_region="ap-south-1",
        connection_status="connected",
    ))
    db.commit()
    return org.id, account.id


def _cleanup_tenant(db, org_id, account_id):
    db.rollback()
    for model in (Finding, Incident, AssetSnapshot, AssetRelationship):
        db.query(model).filter(model.organization_id == org_id).delete(synchronize_session=False)
    # CloudAsset has no organization_id; it is owned through the account.
    db.query(CloudAsset).filter(CloudAsset.account_id == account_id).delete(synchronize_session=False)
    db.query(ScanJob).filter(ScanJob.organization_id == org_id).delete(synchronize_session=False)
    db.commit()
    for model, column in ((CloudAccountV2, CloudAccountV2.id), (CloudAccount, CloudAccount.id)):
        db.query(model).filter(column == account_id).delete(synchronize_session=False)
    db.query(Organization).filter(Organization.id == org_id).delete(synchronize_session=False)
    db.commit()


def _patch_session(monkeypatch, fake_or_callable):
    if callable(fake_or_callable) and not isinstance(fake_or_callable, FakeAWS):
        async def _session(self):
            return fake_or_callable()
    else:
        async def _session(self):
            return fake_or_callable
    monkeypatch.setattr(ScanOrchestrator, "_get_aws_session", _session)


async def _run_scan(db, org_id, account_id):
    """Run one full orchestrator scan synchronously and return its ScanJob id."""
    orch = ScanOrchestrator(cloud_account_id=str(account_id), organization_id=str(org_id))
    job = ScanJob(
        id=uuid.uuid4(),
        cloud_account_id=account_id,
        organization_id=org_id,
        status=ScanStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
        region="ap-south-1",
    )
    db.add(job)
    db.commit()
    orch.scan_job = job
    try:
        await orch._run_scan()
    finally:
        orch.db.close()
    db.expire_all()
    return job.id


def _counts(db, org_id, account_id):
    return {
        "assets": db.query(CloudAsset).filter(CloudAsset.account_id == account_id).count(),
        "relationships": db.query(AssetRelationship)
        .filter(AssetRelationship.organization_id == org_id).count(),
        "findings": db.query(Finding).filter(Finding.organization_id == org_id).count(),
        "incidents": db.query(Incident).filter(Incident.organization_id == org_id).count(),
        "snapshots": db.query(AssetSnapshot).filter(AssetSnapshot.organization_id == org_id).count(),
    }


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ----------------------------------------------------------------------------- tests
@pytest.mark.asyncio
async def test_full_scan_persists_every_stage(db, monkeypatch):
    org_id, account_id = _create_tenant(db, "pipeline")
    try:
        _patch_session(monkeypatch, FakeAWS(**COLLECTOR_SIZES))
        job_id = await _run_scan(db, org_id, account_id)

        job = db.query(ScanJob).filter_by(id=job_id).one()
        assert job.status == ScanStatus.COMPLETED
        assert job.error_summary is None
        assert job.assets_discovered > 0
        assert job.findings_generated > 0
        assert set((job.collector_status or {}).values()) == {"completed"}, job.collector_status

        counts = _counts(db, org_id, account_id)
        assert counts["assets"] == job.assets_discovered
        assert counts["findings"] == job.findings_generated > 0
        assert counts["relationships"] > 0
        assert counts["incidents"] > 0
        assert counts["snapshots"] > 0

        # Child/detail rows are attached to the persisted parent assets.
        child_rows = db.execute(text("""
            SELECT
              (SELECT count(*) FROM ec2_instances) +
              (SELECT count(*) FROM s3_buckets) +
              (SELECT count(*) FROM iam_users) +
              (SELECT count(*) FROM security_groups)
        """)).scalar()
        assert child_rows > 0

        # Foreign-key integrity: every asset points at a real v2 account.
        orphans = db.execute(text("""
            SELECT count(*) FROM cloud_assets a
            LEFT JOIN cloud_accounts_v2 v ON v.id = a.account_id
            WHERE a.account_id = :account_id AND v.id IS NULL
        """), {"account_id": account_id}).scalar()
        assert orphans == 0

        # Every relationship belongs to this tenant and references known resources.
        rels = db.query(AssetRelationship).filter(AssetRelationship.organization_id == org_id).all()
        assert rels
        asset_ids = {a.resource_id for a in db.query(CloudAsset).filter(CloudAsset.account_id == account_id)}
        assert any(r.source_asset_id in asset_ids for r in rels)

        # Findings are fully attributed and fingerprinted.
        findings = db.query(Finding).filter(Finding.organization_id == org_id).all()
        assert {f.cloud_provider for f in findings} == {"AWS"}
        assert all(f.fingerprint for f in findings)
        assert len({f.fingerprint for f in findings}) == len(findings)
        assert {f.severity for f in findings} <= {"critical", "high", "medium", "low", "info"}

        incidents = db.query(Incident).filter(Incident.organization_id == org_id).all()
        assert all(i.correlation_fingerprint for i in incidents)
        assert all(i.finding_ids for i in incidents)
    finally:
        _cleanup_tenant(db, org_id, account_id)


@pytest.mark.asyncio
async def test_repeat_scan_is_idempotent(db, monkeypatch):
    org_id, account_id = _create_tenant(db, "idempotent")
    try:
        _patch_session(monkeypatch, FakeAWS(**COLLECTOR_SIZES))
        first_job = await _run_scan(db, org_id, account_id)
        first = _counts(db, org_id, account_id)
        first_fingerprints = {f.fingerprint for f in db.query(Finding).filter(Finding.organization_id == org_id)}
        first_incident_keys = {
            i.correlation_fingerprint for i in db.query(Incident).filter(Incident.organization_id == org_id)
        }

        second_job = await _run_scan(db, org_id, account_id)
        second = _counts(db, org_id, account_id)
        second_fingerprints = {f.fingerprint for f in db.query(Finding).filter(Finding.organization_id == org_id)}
        second_incident_keys = {
            i.correlation_fingerprint for i in db.query(Incident).filter(Incident.organization_id == org_id)
        }

        assert db.query(ScanJob).filter_by(id=first_job).one().status == ScanStatus.COMPLETED
        assert db.query(ScanJob).filter_by(id=second_job).one().status == ScanStatus.COMPLETED

        assert second["assets"] == first["assets"]
        assert second["relationships"] == first["relationships"]
        assert second["findings"] == first["findings"]
        assert second_fingerprints == first_fingerprints
        assert second_incident_keys == first_incident_keys
        # Unchanged configurations must not create new snapshot versions.
        assert second["snapshots"] == first["snapshots"]
    finally:
        _cleanup_tenant(db, org_id, account_id)


@pytest.mark.asyncio
async def test_all_collectors_failed_is_reported_as_failed_scan(db, monkeypatch):
    """A scan with zero successful collectors must not be marked completed."""
    org_id, account_id = _create_tenant(db, "collector-outage")
    try:
        from app.cloud.aws.collectors import (
            ec2, iam, rds, s3, security_groups, subnets, vpc,
        )

        async def _boom(self):
            raise RuntimeError("AWS credentials rejected")

        for module in (ec2, iam, rds, s3, security_groups, subnets, vpc):
            for value in vars(module).values():
                if isinstance(value, type) and value.__module__ == module.__name__:
                    if hasattr(value, "collect"):
                        monkeypatch.setattr(value, "collect", _boom)

        _patch_session(monkeypatch, FakeAWS(**COLLECTOR_SIZES))
        job_id = await _run_scan(db, org_id, account_id)

        job = db.query(ScanJob).filter_by(id=job_id).one()
        assert job.status == ScanStatus.FAILED
        assert "All AWS collectors failed" in (job.error_summary or "")
        counts = _counts(db, org_id, account_id)
        assert counts["assets"] == 0
        assert counts["findings"] == 0
    finally:
        _cleanup_tenant(db, org_id, account_id)


@pytest.mark.asyncio
async def test_aws_failure_marks_scan_failed_without_partial_data(db, monkeypatch):
    org_id, account_id = _create_tenant(db, "failure")
    try:
        def _boom():
            raise RuntimeError("AWS credentials rejected")

        _patch_session(monkeypatch, _boom)
        job_id = await _run_scan(db, org_id, account_id)

        job = db.query(ScanJob).filter_by(id=job_id).one()
        assert job.status == ScanStatus.FAILED
        assert job.error_summary and "RuntimeError" in job.error_summary
        counts = _counts(db, org_id, account_id)
        assert counts["assets"] == 0
        assert counts["findings"] == 0
    finally:
        _cleanup_tenant(db, org_id, account_id)


@pytest.mark.asyncio
async def test_scan_does_not_leak_across_tenants(db, monkeypatch):
    org_a, account_a = _create_tenant(db, "tenant-a")
    org_b, account_b = _create_tenant(db, "tenant-b")
    try:
        _patch_session(monkeypatch, FakeAWS(**COLLECTOR_SIZES))
        await _run_scan(db, org_a, account_a)

        assert _counts(db, org_a, account_a)["assets"] > 0
        assert _counts(db, org_a, account_a)["findings"] > 0
        # Tenant B has no scan data at all.
        assert _counts(db, org_b, account_b) == {
            "assets": 0, "relationships": 0, "findings": 0, "incidents": 0, "snapshots": 0,
        }

        # ...and a scan of tenant B never touches tenant A's rows.
        before_a = _counts(db, org_a, account_a)
        await _run_scan(db, org_b, account_b)
        assert _counts(db, org_a, account_a) == before_a
        assert _counts(db, org_b, account_b)["findings"] > 0
    finally:
        _cleanup_tenant(db, org_a, account_a)
        _cleanup_tenant(db, org_b, account_b)


@pytest.mark.asyncio
async def test_report_api_exports_only_scanned_tenant(db, monkeypatch):
    org_a, account_a = _create_tenant(db, "report-a")
    org_b, account_b = _create_tenant(db, "report-b")
    try:
        _patch_session(monkeypatch, FakeAWS(**COLLECTOR_SIZES))
        await _run_scan(db, org_a, account_a)

        from app.main import app
        from app.api.v1 import reports as reports_module
        from app.core.security import get_current_user
        from app.database import get_db

        expected = db.query(Finding).filter(Finding.organization_id == org_a).count()
        assert expected > 0

        def _override_db():
            yield db

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = lambda: {
            "id": str(uuid.uuid4()),
            "organization_id": str(org_a),
        }
        monkeypatch.setattr(reports_module, "get_current_organization", lambda user, session: str(org_a))
        try:
            with TestClient(app) as client:
                response = client.get("/api/v1/reports/export", params={"format": "json"})
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200, response.text
        payload = response.json()
        assert len(payload) == expected
        assert {row["cloud_provider"] for row in payload} == {"AWS"}
        assert all(row["rule_id"] and row["resource_id"] for row in payload)

        # Switching tenant returns that tenant's (empty) report instead.
        monkeypatch.setattr(reports_module, "get_current_organization", lambda user, session: str(org_b))
        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = lambda: {
            "id": str(uuid.uuid4()),
            "organization_id": str(org_b),
        }
        try:
            with TestClient(app) as client:
                other = client.get("/api/v1/reports/export", params={"format": "json"})
        finally:
            app.dependency_overrides.clear()
        assert other.status_code == 200
        assert other.json() == []
    finally:
        _cleanup_tenant(db, org_a, account_a)
        _cleanup_tenant(db, org_b, account_b)
