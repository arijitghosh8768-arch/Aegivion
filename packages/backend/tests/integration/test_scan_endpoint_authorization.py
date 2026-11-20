"""Authorization tests for ``POST /api/v1/findings/scan`` (Scan Now).

The route and the scanner service are exercised with a real PostgreSQL session
so account ownership is checked against real rows, while AWS discovery itself is
patched out (no AWS calls are made in this file).
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.database import SessionLocal
from app.models.cloud import CloudAccount
from app.models.organization import Organization
from app.models.cloud_account import CloudAccountV2
from app.services import scanner


def _request(account_id: str | None = None) -> Request:
    query = f"account_id={account_id}".encode() if account_id else b""
    return Request({"type": "http", "method": "POST", "path": "/api/v1/findings/scan",
                    "query_string": query, "headers": []})


def _create_org(db, label):
    org = Organization(id=uuid.uuid4(), name=f"Auth {label}", slug=f"auth-{label}-{uuid.uuid4().hex[:8]}")
    db.add(org)
    db.flush()
    return org.id


def _create_account(db, org_id, label):
    account = CloudAccount(
        id=uuid.uuid4(),
        organization_id=org_id,
        name=f"Auth AWS {label}",
        provider="AWS",
        aws_region="ap-south-1",
        status="connected",
    )
    db.add(account)
    db.flush()
    db.add(CloudAccountV2(
        id=account.id,
        organization_id=org_id,
        provider="aws",
        account_id="111122223333",
        account_name=f"Auth AWS {label}",
        default_region="ap-south-1",
        connection_status="connected",
    ))
    db.commit()
    return account.id


def _cleanup(db, org_id, account_id):
    db.rollback()
    db.query(CloudAccountV2).filter(CloudAccountV2.id == account_id).delete(synchronize_session=False)
    db.query(CloudAccount).filter(CloudAccount.id == account_id).delete(synchronize_session=False)
    db.query(Organization).filter(Organization.id == org_id).delete(synchronize_session=False)
    db.commit()


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    # The route is rate limited to 2/minute; direct calls share one IP bucket.
    from app.api.v1 import findings as findings_module
    from app.api.v1 import integration as integration_module

    findings_module.limiter.reset()
    integration_module.limiter.reset()
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_resolve_account_rejects_another_tenants_account(db):
    org_a = _create_org(db, "owner")
    org_b = _create_org(db, "other")
    account_b = _create_account(db, org_b, "b")
    try:
        with pytest.raises(LookupError):
            scanner._resolve_account(db, str(account_b), str(org_a))
    finally:
        _cleanup(db, org_a, uuid.uuid4())
        _cleanup(db, org_b, account_b)


def test_resolve_account_is_scoped_to_tenant(db):
    org_a = _create_org(db, "scope")
    account_a = _create_account(db, org_a, "a")
    try:
        # Explicit account of the tenant resolves.
        assert scanner._resolve_account(db, str(account_a), str(org_a)).id == account_a
        # No account_id: the tenant's own first account, never another tenant's.
        assert scanner._resolve_account(db, None, str(org_a)).id == account_a
        # A tenant with no accounts gets a ValueError -> HTTP 400.
        empty_org = _create_org(db, "empty")
        with pytest.raises(ValueError):
            scanner._resolve_account(db, None, str(empty_org))
        _cleanup(db, empty_org, uuid.uuid4())
    finally:
        _cleanup(db, org_a, account_a)


def test_scan_route_forwards_caller_tenant_and_account(db, monkeypatch):
    from app.api.v1 import findings as findings_module

    org_a = _create_org(db, "route")
    account_a = _create_account(db, org_a, "route")
    calls = {}

    def _fake_scan(session, account_id=None, organization_id=None):
        calls["account_id"] = account_id
        calls["organization_id"] = organization_id
        return {"success": True, "scanned_assets_count": 0, "findings_count": 0}

    monkeypatch.setattr(findings_module, "run_cloud_scan", _fake_scan)
    monkeypatch.setattr(findings_module, "get_current_organization", lambda user, session: str(org_a))
    try:
        response = findings_module.trigger_cloud_scan(
            _request(str(account_a)), db=db, current_user={"id": str(uuid.uuid4())}
        )
        assert response["success"] is True
        assert calls == {"account_id": str(account_a), "organization_id": str(org_a)}
    finally:
        _cleanup(db, org_a, account_a)


def test_scan_route_returns_404_for_foreign_account(db, monkeypatch):
    from app.api.v1 import findings as findings_module

    org_a = _create_org(db, "attacker")
    org_b = _create_org(db, "victim")
    account_b = _create_account(db, org_b, "victim")
    monkeypatch.setattr(findings_module, "get_current_organization", lambda user, session: str(org_a))
    try:
        with pytest.raises(HTTPException) as exc:
            findings_module.trigger_cloud_scan(
                _request(str(account_b)), db=db, current_user={"id": str(uuid.uuid4())}
            )
        assert exc.value.status_code == 404
        # No scan was started against the victim account.
        assert db.query(scanner.CloudAccount).filter_by(id=account_b).one().last_scan_at is None
    finally:
        _cleanup(db, org_a, uuid.uuid4())
        _cleanup(db, org_b, account_b)


def test_scan_route_returns_400_when_no_account(db, monkeypatch):
    from app.api.v1 import findings as findings_module

    org = _create_org(db, "noaccount")
    monkeypatch.setattr(findings_module, "get_current_organization", lambda user, session: str(org))
    try:
        with pytest.raises(HTTPException) as exc:
            findings_module.trigger_cloud_scan(_request(), db=db, current_user={"id": str(uuid.uuid4())})
        assert exc.value.status_code == 400
        assert "no tenant account" in exc.value.detail
    finally:
        _cleanup(db, org, uuid.uuid4())


@pytest.mark.asyncio
async def test_orchestrator_scan_start_rejects_foreign_account(db, monkeypatch):
    from app.api.v1 import integration as integration_module

    org_a = _create_org(db, "start-attacker")
    org_b = _create_org(db, "start-victim")
    account_b = _create_account(db, org_b, "start-victim")
    called = False

    async def _fake_start(self):
        nonlocal called
        called = True
        return {"scan_id": str(uuid.uuid4()), "status": "queued"}

    monkeypatch.setattr(integration_module.ScanOrchestrator, "start_scan", _fake_start)
    monkeypatch.setattr(integration_module, "get_current_organization", lambda user, session: str(org_a))
    try:
        with pytest.raises(HTTPException) as exc:
            await integration_module.start_scan(
                _request(),
                integration_module.ScanRequest(cloud_account_id=str(account_b)),
                db=db,
                current_user={"id": str(uuid.uuid4())},
            )
        assert exc.value.status_code == 404
        assert called is False
    finally:
        _cleanup(db, org_a, uuid.uuid4())
        _cleanup(db, org_b, account_b)


@pytest.mark.asyncio
async def test_orchestrator_scan_start_uses_tenant_account(db, monkeypatch):
    from app.api.v1 import integration as integration_module

    org = _create_org(db, "start-own")
    account = _create_account(db, org, "start-own")
    seen = {}

    async def _fake_start(self):
        seen["account"] = self.cloud_account_id
        seen["org"] = self.organization_id
        self.db.close()
        return {"scan_id": str(uuid.uuid4()), "status": "queued"}

    monkeypatch.setattr(integration_module.ScanOrchestrator, "start_scan", _fake_start)
    monkeypatch.setattr(integration_module, "get_current_organization", lambda user, session: str(org))
    try:
        response = await integration_module.start_scan(
            _request(),
            integration_module.ScanRequest(cloud_account_id=str(account)),
            db=db,
            current_user={"id": str(uuid.uuid4())},
        )
        assert response.status == "queued"
        assert seen == {"account": str(account), "org": str(org)}
    finally:
        _cleanup(db, org, account)


@pytest.mark.asyncio
async def test_scan_status_is_tenant_scoped(db, monkeypatch):
    from app.api.v1 import integration as integration_module
    from app.models.cloud import ScanJob, ScanStatus

    org_a = _create_org(db, "status-a")
    org_b = _create_org(db, "status-b")
    account_a = _create_account(db, org_a, "status-a")
    account_b = _create_account(db, org_b, "status-b")
    job = ScanJob(
        id=uuid.uuid4(),
        cloud_account_id=account_a,
        organization_id=org_a,
        status=ScanStatus.COMPLETED,
        assets_discovered=7,
        findings_generated=3,
    )
    db.add(job)
    db.commit()
    try:
        monkeypatch.setattr(integration_module, "get_current_organization", lambda user, session: str(org_a))
        own = await integration_module.get_scan_status(str(job.id), db=db,
                                                      current_user={"id": str(uuid.uuid4())})
        assert own["status"] == "completed"
        assert own["assets_discovered"] == 7

        monkeypatch.setattr(integration_module, "get_current_organization", lambda user, session: str(org_b))
        with pytest.raises(HTTPException) as exc:
            await integration_module.get_scan_status(str(job.id), db=db,
                                                      current_user={"id": str(uuid.uuid4())})
        assert exc.value.status_code == 404
    finally:
        db.query(ScanJob).filter(ScanJob.id == job.id).delete(synchronize_session=False)
        db.commit()
        _cleanup(db, org_a, account_a)
        _cleanup(db, org_b, account_b)


def test_scan_route_maps_failures_to_500(db, monkeypatch):
    from app.api.v1 import findings as findings_module

    org = _create_org(db, "failure")
    account = _create_account(db, org, "failure")

    def _boom(session, account_id=None, organization_id=None):
        raise RuntimeError("AWS unavailable")

    monkeypatch.setattr(findings_module, "run_cloud_scan", _boom)
    monkeypatch.setattr(findings_module, "get_current_organization", lambda user, session: str(org))
    try:
        with pytest.raises(HTTPException) as exc:
            findings_module.trigger_cloud_scan(
                _request(str(account)), db=db, current_user={"id": str(uuid.uuid4())}
            )
        assert exc.value.status_code == 500
        assert "AWS unavailable" in exc.value.detail
    finally:
        _cleanup(db, org, account)
