"""AWS scan performance benchmark (before/after optimization).

Runs three phases against the *same* deterministic AWS fixtures:

1. ``collectors``  - the modern collectors used by ``ScanOrchestrator``
2. ``orchestrator`` - collectors + asset persistence + detection + correlation + compliance
3. ``scanner``     - the legacy ``run_cloud_scan`` path used by ``POST /api/v1/findings/scan``

AWS latency is *simulated* by sleeping on each fake API call (default 30 ms).
Postgres work is real and runs against ``AEGIVION_BENCH_DATABASE_URL``.

Usage (from ``packages/backend``)::

    python tests/perf/bench_scan.py --phase all --latency 0.03 --out before.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

DEFAULT_DB = os.environ.get(
    "AEGIVION_BENCH_DATABASE_URL",
    "postgresql://aegivion@localhost:5433/aegivion_bench",
)

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
PACKAGES_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
for path in (BACKEND_DIR, PACKAGES_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

os.environ.setdefault("DATABASE_URL", os.environ.get("AEGIVION_BENCH_DATABASE_URL", DEFAULT_DB))
os.environ.setdefault("ENVIRONMENT", "test")

from tests.perf.fake_aws import FakeAWS  # noqa: E402

from app.database import SessionLocal, engine  # noqa: E402
from app.models.cloud import CloudAccount, ScanJob, ScanStatus  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.user import User  # noqa: E402
from app.models.role import Role  # noqa: E402
from app.models.finding import Finding  # noqa: E402
from app.models.cloud import CloudAsset  # noqa: E402
from app.models.incident import Incident  # noqa: E402
from app.models.history import AssetSnapshot  # noqa: E402
from app.models.cloud import Relationship, AssetRelationship  # noqa: E402


def _create_org_and_account(db, provider="AWS"):
    org = Organization(
        id=uuid.uuid4(),
        name=f"Bench Org {uuid.uuid4().hex[:6]}",
        slug=f"bench-{uuid.uuid4().hex[:10]}",
        subscription_plan="enterprise",
    )
    db.add(org)
    db.flush()

    account = CloudAccount(
        id=uuid.uuid4(),
        organization_id=org.id,
        name="Bench AWS",
        provider=provider,
        aws_region="ap-south-1",
        status="connected",
    )
    db.add(account)
    db.flush()

    # cloud_assets carries an FK to the canonical cloud_accounts_v2 row
    from app.models.cloud_account import CloudAccountV2

    db.add(
        CloudAccountV2(
            id=account.id,
            organization_id=org.id,
            provider="aws",
            account_id="111122223333",
            account_name="Bench AWS",
            default_region="ap-south-1",
            connection_status="connected",
        )
    )
    db.commit()
    org_id, account_id = org.id, account.id
    db.close()
    return org_id, account_id


def _cleanup(db, org_id):
    for model in (Finding, Incident, AssetSnapshot, AssetRelationship, Relationship, CloudAsset, ScanJob):
        try:
            db.query(model).filter(getattr(model, "organization_id", None) == org_id).delete(synchronize_session=False)
        except Exception:  # table may not be part of the current schema
            db.rollback()
    try:
        db.commit()
    except Exception:
        db.rollback()


async def _patch_orchestrator_session(fake: FakeAWS):
    from app.cloud.aws.scan.orchestrator import ScanOrchestrator

    async def _fake_session(self):  # noqa: ANN001
        return fake

    ScanOrchestrator._get_aws_session = _fake_session  # type: ignore[assignment]


async def phase_collectors(fake: FakeAWS):
    from app.cloud.aws.scan.orchestrator import ScanOrchestrator

    await _patch_orchestrator_session(fake)
    orch = ScanOrchestrator(cloud_account_id=str(uuid.uuid4()), organization_id=str(uuid.uuid4()))
    results = {}
    total_start = time.perf_counter()
    collectors = orch._initialize_collectors(fake)
    for name, collector in collectors.items():
        fake.reset_counters()
        started = time.perf_counter()
        assets = await collector.collect()
        results[name] = {
            "duration_s": round(time.perf_counter() - started, 3),
            "assets": len(assets),
            "api_calls": fake.total_calls,
            "calls_by_op": dict(fake.calls),
        }
    orch.db.close()
    return {
        "duration_s": round(time.perf_counter() - total_start, 3),
        "total_api_calls": sum(r["api_calls"] for r in results.values()),
        "collectors": results,
    }


async def phase_orchestrator(fake: FakeAWS, items: int = 0):
    from app.cloud.aws.scan.orchestrator import ScanOrchestrator

    await _patch_orchestrator_session(fake)
    org_id, account_id = _create_org_and_account(SessionLocal())

    fake.reset_counters()
    total_start = time.perf_counter()

    orch = ScanOrchestrator(cloud_account_id=str(account_id), organization_id=str(org_id))
    orch.scan_job = None
    db = orch.db

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

    timings = {}
    assets = []

    started = time.perf_counter()
    collectors = orch._initialize_collectors(await orch._get_aws_session())
    collector_results = await orch._run_collectors(collectors)
    timings["collectors"] = round(time.perf_counter() - started, 3)
    collector_assets = {name: res for name, res in collector_results.items()}
    for res in collector_results.values():
        if res["success"]:
            assets.extend(res["assets"])

    started = time.perf_counter()
    persisted = await orch._persist_assets(assets)
    timings["persist_assets"] = round(time.perf_counter() - started, 3)

    started = time.perf_counter()
    await orch._build_relationships(assets)
    timings["relationships"] = round(time.perf_counter() - started, 3)

    started = time.perf_counter()
    findings = await orch._trigger_rule_engine(assets)
    timings["detection"] = round(time.perf_counter() - started, 3)

    started = time.perf_counter()
    incidents = await orch._correlate_incidents(assets)
    timings["correlation"] = round(time.perf_counter() - started, 3)

    started = time.perf_counter()
    await orch._sync_compliance()
    timings["compliance"] = round(time.perf_counter() - started, 3)

    total = round(time.perf_counter() - total_start, 3)

    db = SessionLocal()
    db_findings = db.query(Finding).filter(Finding.organization_id == org_id).count()
    db_incidents = db.query(Incident).filter(Incident.organization_id == org_id).count()
    db_assets = db.query(CloudAsset).filter(CloudAsset.account_id == account_id).count()
    _cleanup(db, org_id)
    from app.models.cloud_account import CloudAccountV2

    db.query(CloudAccountV2).filter(CloudAccountV2.id == account_id).delete()
    db.query(CloudAccount).filter(CloudAccount.id == account_id).delete()
    db.query(Organization).filter(Organization.id == org_id).delete()
    db.commit()
    db.close()
    orch.db.close()

    return {
        "duration_s": total,
        "stage_duration_s": timings,
        "total_api_calls": fake.total_calls,
        "assets_collected": len(assets),
        "assets_persisted": persisted,
        "db_assets": db_assets,
        "findings_generated": findings,
        "db_findings": db_findings,
        "incidents": incidents,
        "db_incidents": db_incidents,
        "collector_status": {k: v["success"] for k, v in collector_assets.items()},
    }


def phase_scanner(fake: FakeAWS):
    """Legacy synchronous scan used by POST /api/v1/findings/scan."""
    import app.services.scanner as scanner

    from app.cloud.aws.scan.orchestrator import ScanOrchestrator

    db = SessionLocal()
    org_id, account_id = _create_org_and_account(db)

    async def _fake_session(self):  # noqa: ANN001
        return fake

    ScanOrchestrator._get_aws_session = _fake_session  # type: ignore[assignment]

    started = time.perf_counter()
    result = {"status": "ok"}
    try:
        result["scan"] = scanner.run_cloud_scan(db, str(account_id))
    except Exception as exc:  # noqa: BLE001
        result = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
    duration = round(time.perf_counter() - started, 3)

    db.rollback()
    _cleanup(db, org_id)
    from app.models.cloud_account import CloudAccountV2

    db.query(CloudAccountV2).filter(CloudAccountV2.id == account_id).delete()
    db.query(CloudAccount).filter(CloudAccount.id == account_id).delete()
    db.query(Organization).filter(Organization.id == org_id).delete()
    db.commit()
    db.close()

    return {
        "duration_s": duration,
        "api_calls": fake.total_calls,
        "result": result,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["collectors", "orchestrator", "scanner", "all"], default="all")
    parser.add_argument("--latency", type=float, default=0.03)
    parser.add_argument("--buckets", type=int, default=120)
    parser.add_argument("--users", type=int, default=40)
    parser.add_argument("--ec2", type=int, default=80)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    output = {"config": vars(args), "latency_model": "simulated per-API-call sleep"}
    fake = FakeAWS(
        latency=args.latency,
        buckets=args.buckets,
        iam_users=args.users,
        ec2_instances=args.ec2,
    )

    if args.phase in ("collectors", "all"):
        output["collectors"] = asyncio.run(phase_collectors(fake))
    if args.phase in ("orchestrator", "all"):
        output["orchestrator"] = asyncio.run(phase_orchestrator(fake))
    if args.phase in ("scanner", "all"):
        if hasattr(engine, "dispose"):
            pass
        fake.reset_counters()
        output["scanner"] = phase_scanner(fake)

    text = json.dumps(output, indent=2, default=str)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)


if __name__ == "__main__":
    main()
