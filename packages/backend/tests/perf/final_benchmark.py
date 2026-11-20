"""Repeatable end-to-end benchmark for the AWS scan and (optionally) RAG path.

Every stage is timed with ``time.perf_counter`` on a real PostgreSQL database;
only the AWS API is deterministic (``tests.perf.fake_aws.FakeAWS``) with an
explicit simulated per-call latency.  Results therefore describe *this*
workload, not a production AWS account.

The database must be a dedicated benchmark database, never the application or
test database.  By default ``aegivion_bench`` on the local pgvector instance is
used; override with ``AEGIVION_BENCH_DATABASE_URL``.

Usage (from ``packages/backend``)::

    python tests/perf/final_benchmark.py --reps 5 --latency 0.03 \
        --out reports/scan_benchmark.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
import tracemalloc
import uuid
from datetime import datetime, timezone

DEFAULT_DB = os.environ.get("AEGIVION_BENCH_DATABASE_URL", "")
# No credentials are committed: point this at a dedicated benchmark DB, e.g.
#   export AEGIVION_BENCH_DATABASE_URL=postgresql://aegivion@localhost:5433/aegivion_bench

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
PACKAGES_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
for path in (BACKEND_DIR, PACKAGES_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

# An explicitly exported TEST_DATABASE_URL would win in app/database/session.py;
# make sure the benchmark always points at its own dedicated database.
os.environ.pop("TEST_DATABASE_URL", None)
os.environ["DATABASE_URL"] = DEFAULT_DB
os.environ["ENVIRONMENT"] = "test"

if not DEFAULT_DB:
    raise SystemExit(
        "AEGIVION_BENCH_DATABASE_URL is required (a dedicated benchmark database, "
        "never the application or test database)"
    )
if "aegivion_bench" not in os.environ["DATABASE_URL"]:
    raise SystemExit("Refusing to benchmark against a non-benchmark database")

from tests.perf.fake_aws import FakeAWS  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.models.cloud import (  # noqa: E402
    AssetRelationship,
    CloudAccount,
    CloudAsset,
    ScanJob,
    ScanStatus,
)
from app.models.cloud_account import CloudAccountV2  # noqa: E402
from app.models.finding import Finding  # noqa: E402
from app.models.history import AssetSnapshot  # noqa: E402
from app.models.incident import Incident  # noqa: E402
from app.models.organization import Organization  # noqa: E402

COLLECTOR_NAMES = ["ec2", "s3", "iam", "security_groups", "vpc", "subnets", "rds"]


def _create_tenant(db):
    org = Organization(
        id=uuid.uuid4(),
        name=f"Bench {uuid.uuid4().hex[:6]}",
        slug=f"bench-{uuid.uuid4().hex[:10]}",
        subscription_plan="enterprise",
    )
    db.add(org)
    db.flush()
    account = CloudAccount(
        id=uuid.uuid4(),
        organization_id=org.id,
        name="Bench AWS",
        provider="AWS",
        aws_region="ap-south-1",
        status="connected",
    )
    db.add(account)
    db.flush()
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
    return org.id, account.id


def _cleanup_tenant(db, org_id, account_id):
    db.rollback()
    for model in (Finding, Incident, AssetSnapshot, AssetRelationship):
        db.query(model).filter(model.organization_id == org_id).delete(synchronize_session=False)
    db.query(CloudAsset).filter(CloudAsset.account_id == account_id).delete(synchronize_session=False)
    db.query(ScanJob).filter(ScanJob.organization_id == org_id).delete(synchronize_session=False)
    db.commit()
    db.query(CloudAccountV2).filter(CloudAccountV2.id == account_id).delete(synchronize_session=False)
    db.query(CloudAccount).filter(CloudAccount.id == account_id).delete(synchronize_session=False)
    db.query(Organization).filter(Organization.id == org_id).delete(synchronize_session=False)
    db.commit()


def _make_job(db, org_id, account_id):
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
    return job


def _patch_session(monkeypatch_target, fake):
    from app.cloud.aws.scan.orchestrator import ScanOrchestrator

    async def _fake_session(self):  # noqa: ANN001
        return fake

    monkeypatch_target._get_aws_session = _fake_session  # type: ignore[assignment]


async def _collect_with_instrumentation(orch, fake):
    from app.cloud.aws.scan.orchestrator import ScanOrchestrator

    collectors = orch._initialize_collectors(fake)
    events = []
    lock = asyncio.Lock()
    in_flight = 0
    peak = 0

    for name, collector in collectors.items():
        original = collector.collect

        def _wrap(original=original, name=name):
            async def _collect():
                nonlocal in_flight, peak
                async with lock:
                    in_flight += 1
                    peak = max(peak, in_flight)
                    events.append((name, "start", time.perf_counter()))
                try:
                    return await original()
                finally:
                    async with lock:
                        in_flight -= 1
                        events.append((name, "end", time.perf_counter()))

            return _collect

        collector.collect = _wrap()

    results = await orch._run_collectors(collectors)
    starts = {name: start for name, kind, start in events if kind == "start"}
    ends = {name: end for name, kind, end in events if kind == "end"}
    overlap = 0.0
    for name in starts:
        for other in starts:
            if name < other:
                overlap = max(
                    overlap,
                    min(ends[name], ends[other]) - max(starts[name], starts[other]),
                )
    return results, {"peak_in_flight": peak, "max_pair_overlap_s": round(overlap, 4)}


async def _staged_scan(sizes, latency, assets_per_scan=True):
    from app.cloud.aws.scan.orchestrator import ScanOrchestrator

    fake = FakeAWS(latency=latency, **sizes)
    _patch_session(ScanOrchestrator, fake)
    db = SessionLocal()
    org_id, account_id = _create_tenant(db)
    job = _make_job(db, org_id, account_id)
    orch = ScanOrchestrator(cloud_account_id=str(account_id), organization_id=str(org_id))
    orch.scan_job = job
    timings = {}
    info = {}
    try:
        fake.reset_counters()
        started = time.perf_counter()
        collectors = orch._initialize_collectors(fake)
        collected, concurrency = await _collect_with_instrumentation(orch, fake)
        timings["collectors"] = time.perf_counter() - started
        info["concurrency"] = concurrency

        assets = []
        for name, result in collected.items():
            if result["success"]:
                assets.extend(result["assets"])
        info["assets_collected"] = len(assets)
        info["api_calls"] = fake.total_calls
        info["collectors_succeeded"] = sum(1 for r in collected.values() if r["success"])

        if assets_per_scan:
            started = time.perf_counter()
            info["assets_persisted"] = await orch._persist_assets(assets)
            timings["persist_assets"] = time.perf_counter() - started

            started = time.perf_counter()
            await orch._build_relationships(assets)
            timings["relationships"] = time.perf_counter() - started

            started = time.perf_counter()
            info["findings"] = await orch._trigger_rule_engine(assets)
            timings["detection"] = time.perf_counter() - started

            started = time.perf_counter()
            info["incidents"] = await orch._correlate_incidents(assets)
            timings["correlation"] = time.perf_counter() - started

            started = time.perf_counter()
            await orch._sync_compliance()
            timings["compliance"] = time.perf_counter() - started

        timings["staged_total"] = sum(timings.values())
        db2 = SessionLocal()
        try:
            info["db_assets"] = db2.query(CloudAsset).filter(CloudAsset.account_id == account_id).count()
            info["db_findings"] = db2.query(Finding).filter(Finding.organization_id == org_id).count()
            info["db_incidents"] = db2.query(Incident).filter(Incident.organization_id == org_id).count()
            info["db_relationships"] = (
                db2.query(AssetRelationship).filter(AssetRelationship.organization_id == org_id).count()
            )
        finally:
            db2.close()
    finally:
        orch.db.close()
        cleanup = SessionLocal()
        try:
            _cleanup_tenant(cleanup, org_id, account_id)
        finally:
            cleanup.close()
    return timings, info


async def _full_scan(sizes, latency, trace=False):
    from app.cloud.aws.scan.orchestrator import ScanOrchestrator

    fake = FakeAWS(latency=latency, **sizes)
    _patch_session(ScanOrchestrator, fake)
    db = SessionLocal()
    org_id, account_id = _create_tenant(db)
    job_id = uuid.uuid4()
    job = ScanJob(
        id=job_id,
        cloud_account_id=account_id,
        organization_id=org_id,
        status=ScanStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
        region="ap-south-1",
    )
    db.add(job)
    db.commit()

    orch = ScanOrchestrator(cloud_account_id=str(account_id), organization_id=str(org_id))
    orch.scan_job = job
    if trace:
        tracemalloc.start()
    cpu_start = time.process_time()
    started = time.perf_counter()
    try:
        await orch._run_scan()
        wall = time.perf_counter() - started
        cpu = time.process_time() - cpu_start
        peak = tracemalloc.get_traced_memory()[1] if trace else None
    finally:
        if trace:
            tracemalloc.stop()
        orch.db.close()
        check = SessionLocal()
        try:
            final = check.query(ScanJob).filter(ScanJob.id == job_id).one()
            status = final.status.value if hasattr(final.status, "value") else str(final.status)
            assets = check.query(CloudAsset).filter(CloudAsset.account_id == account_id).count()
            findings = check.query(Finding).filter(Finding.organization_id == org_id).count()
            relationships = (
                check.query(AssetRelationship)
                .filter(AssetRelationship.organization_id == org_id)
                .count()
            )
            _cleanup_tenant(check, org_id, account_id)
        finally:
            check.close()
    return {
        "wall_s": round(wall, 4),
        "cpu_s": round(cpu, 4),
        "peak_python_mem_mb": round(peak / (1024 * 1024), 2) if peak is not None else None,
        "status": status,
        "db_assets": assets,
        "db_findings": findings,
        "db_relationships": relationships,
        "api_calls": fake.total_calls,
    }


def _scan_now_service(sizes, latency):
    """Time the service behind ``POST /api/v1/findings/scan`` (route body)."""
    from app.cloud.aws.scan.orchestrator import ScanOrchestrator
    from app.services import scanner

    fake = FakeAWS(latency=latency, **sizes)
    _patch_session(ScanOrchestrator, fake)
    # The legacy Scan Now service consumes its own discovery format, so AWS is
    # replaced at the discovery boundary.  This measures the API/DB overhead of
    # that path; collector I/O is measured by the staged benchmark above.
    bucket = {
        "bucket_name": "bench-bucket-000",
        "arn": "arn:aws:s3:::bench-bucket-000",
        "region": "ap-south-1",
        "is_public": True,
        "encryption_enabled": True,
        "versioning_enabled": True,
    }
    instance = {
        "instance_id": "i-bench0001",
        "state": "running",
        "public_ip": "203.0.113.10",
        "private_ip": "10.0.0.10",
        "instance_type": "t3.micro",
        "security_groups": [{"GroupId": "sg-bench"}],
        "has_public_ip": True,
        "region": "ap-south-1",
    }
    user = {
        "username": "bench-user-00",
        "arn": "arn:aws:iam::111122223333:user/bench-user-00",
        "mfa_enabled": False,
        "is_admin": True,
        "access_keys_age_days": 120,
        "last_active": None,
    }
    group = {
        "group_id": "sg-bench",
        "group_name": "bench-sg",
        "vpc_id": "vpc-bench",
        "region": "ap-south-1",
        "ingress_rules": [
            {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
        "egress_rules": [],
    }
    vpc = {"vpc_id": "vpc-bench", "cidr_block": "10.0.0.0/16", "region": "ap-south-1"}
    rds = {
        "db_instance_identifier": "bench-db-00",
        "arn": "arn:aws:rds:ap-south-1:111122223333:db:bench-db-00",
        "region": "ap-south-1",
        "publicly_accessible": True,
        "storage_encrypted": False,
    }
    trail = {"trail_name": "bench-trail", "arn": "arn:aws:cloudtrail:ap-south-1:111122223333:trail/bench", "is_logging": False, "region": "ap-south-1", "multi_region": True}

    originals = {}
    fixtures = {
        "discover_s3_buckets": [bucket] * 10,
        "discover_ec2_instances": [instance],
        "discover_iam_users": [user],
        "discover_rds_instances": [rds],
        "discover_security_groups": [group],
        "discover_vpcs": [vpc],
        "discover_cloudtrail_trails": [trail],
    }
    for name, value in fixtures.items():
        originals[name] = getattr(scanner, name)
        setattr(scanner, name, lambda session=None, value=value: list(value))

    db = SessionLocal()
    org_id, account_id = _create_tenant(db)
    try:
        started = time.perf_counter()
        result = scanner.run_cloud_scan(
            db, account_id=str(account_id), organization_id=str(org_id)
        )
        elapsed = time.perf_counter() - started
        return {
            "wall_s": round(elapsed, 4),
            "status": "success" if (result or {}).get("success") else "error",
            "scanned_assets": (result or {}).get("scanned_assets_count", 0),
            "db_assets": db.query(CloudAsset).filter(CloudAsset.account_id == account_id).count(),
            "db_findings": db.query(Finding).filter(Finding.organization_id == org_id).count(),
        }
    finally:
        for name, original in originals.items():
            setattr(scanner, name, original)
        try:
            _cleanup_tenant(db, org_id, account_id)
        finally:
            db.close()


def _aggregate(rows, key):
    values = [row[key] for row in rows if row.get(key) is not None]
    if not values:
        return {}
    return {
        "n": len(values),
        "median": round(statistics.median(values), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--latency", type=float, default=0.03)
    parser.add_argument("--buckets", type=int, default=120)
    parser.add_argument("--users", type=int, default=40)
    parser.add_argument("--ec2", type=int, default=80)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    sizes = dict(
        buckets=args.buckets,
        iam_users=args.users,
        iam_roles=25,
        iam_groups=10,
        iam_policies=15,
        ec2_instances=args.ec2,
        security_groups=60,
        vpcs=12,
        subnets=40,
        rds_instances=6,
    )

    staged_rows = []
    full_rows = []
    for _ in range(args.reps):
        timings, info = asyncio.run(_staged_scan(sizes, args.latency))
        staged_rows.append({**timings, **info})
        full_rows.append(asyncio.run(_full_scan(sizes, args.latency)))

    # One traced pass for allocation peak; traced runs are excluded from timing.
    traced = asyncio.run(_full_scan(sizes, args.latency, trace=True))

    service_rows = [_scan_now_service(sizes, args.latency) for _ in range(min(3, args.reps))]

    stage_keys = [
        "collectors",
        "persist_assets",
        "relationships",
        "detection",
        "correlation",
        "compliance",
        "staged_total",
    ]
    output = {
        "environment": {
            "database": "postgresql://aegivion@localhost:5433/aegivion_bench",
            "aws": "simulated (FakeAWS)",
            "simulated_latency_per_api_call_s": args.latency,
            "collectors": COLLECTOR_NAMES,
            "resources": sizes,
        },
        "repetitions": args.reps,
        "stage_seconds": {key: _aggregate(staged_rows, key) for key in stage_keys},
        "per_run_stage_seconds": [
            {key: round(row.get(key, 0), 4) for key in stage_keys} for row in staged_rows
        ],
        "workload": {
            "assets_collected": staged_rows[0]["assets_collected"],
            "assets_persisted": staged_rows[0]["assets_persisted"],
            "api_calls": staged_rows[0]["api_calls"],
            "collectors_succeeded": staged_rows[0]["collectors_succeeded"],
            "db_assets": staged_rows[0]["db_assets"],
            "db_findings": staged_rows[0]["db_findings"],
            "db_incidents": staged_rows[0]["db_incidents"],
            "db_relationships": staged_rows[0]["db_relationships"],
            "peak_collector_in_flight": staged_rows[0]["concurrency"]["peak_in_flight"],
            "max_pair_overlap_s": staged_rows[0]["concurrency"]["max_pair_overlap_s"],
        },
        "full_orchestration": {
            key: _aggregate(full_rows, key) for key in (
                "wall_s", "cpu_s", "peak_python_mem_mb", "db_assets", "db_findings", "api_calls"
            )
        } | {
            "statuses": [row["status"] for row in full_rows],
            "traced_peak_python_mem_mb": traced["peak_python_mem_mb"],
        },
        "scan_now_service": {
            key: _aggregate(service_rows, key)
            for key in ("wall_s", "scanned_assets", "db_assets", "db_findings")
        } | {"statuses": [row["status"] for row in service_rows]},
        "p95_note": "p95 omitted: fewer than 20 samples per phase",
    }

    text = json.dumps(output, indent=2, default=str)
    print(text)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)


if __name__ == "__main__":
    main()
