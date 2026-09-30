"""End-to-end scenario fixtures.

Each scenario mirrors one of the ten required test cases and produces
provider dicts ready for normalization.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from .cloudtrail_records import NORM

_SEQ = iter(range(1000))


def _event_id() -> str:
    n = next(_SEQ)
    return f"eeeeeeee-0000-4000-8000-{n:012d}"


def _get(bucket: str, key: str, *, t: datetime, out: int, ip: str | None = "203.0.113.10",
         region: str = "us-east-1", actor: dict | None = None, ua: str | None = NORM["userAgent"]) -> dict:
    base = {**NORM, "arn": (actor or {}).get("arn", NORM["arn"]), "type": (actor or {}).get("type", NORM["type"])}
    rec = {
        **base,
        "eventID": _event_id(),
        "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "awsRegion": region,
        "eventName": "GetObject",
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": {"bucketName": bucket, "key": key},
        "additionalEventData": {"bytesTransferredOut": out},
    }
    return rec


def _list(bucket: str, *, t: datetime, prefix: str = "exports/", truncated: bool = True) -> dict:
    return {
        **NORM,
        "eventID": _event_id(),
        "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": "ListObjectsV2",
        "requestParameters": {"bucketName": bucket, "prefix": prefix, "maxResults": 1000},
        "responseElements": {"isTruncated": "true" if truncated else "false"},
        "additionalEventData": None,
    }


def scenario_normal_s3_access() -> list[dict]:
    """1. normal S3 access: a handful of small reads, same bucket, same hour."""
    t0 = datetime(2024, 11, 14, 3, 0, tzinfo=timezone.utc)
    return [_get("app-assets", f"img/{i}.png", t=t0 + timedelta(seconds=i * 20), out=25_000) for i in range(4)]


def scenario_legit_backup() -> list[dict]:
    """2. high-volume legitimate backup: assumed-role, one bucket, sustained."""
    t0 = datetime(2024, 11, 14, 1, 0, tzinfo=timezone.utc)
    actor = {"arn": NORM.get("arn", ""), "type": "AssumedRole"}
    events = []
    for i in range(6):
        rec = _get("backups-prod", f"nightly/part-{i}.tar", t=t0 + timedelta(minutes=i * 4), out=500_000_000)
        rec["arn"] = "arn:aws:sts::111122223333:assumed-role/BackupOperator/backup-job-42"
        rec["type"] = "AssumedRole"
        rec["userAgent"] = "aws-sdk-go/1.44 (backup-agent)"
        events.append(rec)
    return events


def scenario_sensitive_access() -> list[dict]:
    """3. sensitive data access: reads from a Macie-flagged bucket."""
    t0 = datetime(2024, 11, 14, 3, 30, tzinfo=timezone.utc)
    return [
        _get("prod-customer-data", "pii/customers-eu.csv", t=t0 + timedelta(seconds=i * 45), out=3_000_000)
        for i in range(3)
    ]


def scenario_unknown_destination() -> list[dict]:
    """4. unknown destination: CopyObject into an attacker-controlled bucket."""
    t0 = datetime(2024, 11, 14, 4, 0, tzinfo=timezone.utc)
    rec = {
        **NORM,
        "eventID": _event_id(),
        "eventTime": t0.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": "CopyObject",
        "requestParameters": {
            "bucketName": "attacker-staging",
            "key": "stolen/customers.csv",
            "x-amz-copy-source": "prod-customer-data/pii/customers-eu.csv",
        },
        "additionalEventData": {"bytesTransferredOut": 3_000_000},
    }
    return [rec]


def scenario_abnormal_enumeration() -> list[dict]:
    """5. abnormal object enumeration: rapid-fire LIST across prefixes."""
    t0 = datetime(2024, 11, 14, 5, 0, tzinfo=timezone.utc)
    return [_list("prod-customer-data", t=t0 + timedelta(seconds=i * 2), prefix=f"p{i}/") for i in range(30)]


def scenario_large_network_egress(flow_reader) -> tuple[list[dict], list]:
    """6. large network egress: S3 reads + matching VPC flow to one external IP."""
    t0 = datetime(2024, 11, 14, 6, 0, tzinfo=timezone.utc)
    events = [_get("prod-customer-data", f"dump/{i}.csv", t=t0 + timedelta(seconds=i * 30), out=80_000_000)
              for i in range(5)]
    flows = []
    for i in range(5):
        start = t0 + timedelta(seconds=i * 30 + 5)
        flows.append({
            "version": 2,
            "interface-id": "eni-0abc1234",
            "account-id": "111122223333",
            "region": "us-east-1",
            "vpc-id": "vpc-123",
            "subnet-id": "subnet-123",
            "instance-id": "-",
            "src-addr": "10.0.1.20",
            "dst-addr": "198.51.100.77",
            "start": int(start.timestamp()),
            "end": int((start + timedelta(seconds=40)).timestamp()),
            "protocol": 6,
            "bytes": 82_000_000,
            "packets": 60_000,
            "tcp-flags": 0x0018,
            "type": "IPv4",
            "pkt-src-addr": "10.0.1.20",
            "pkt-dst-addr": "198.51.100.77",
        })
    return events, flows


def scenario_slow_movement() -> list[dict]:
    """7. slow data movement: small steady reads stretched over many hours."""
    t0 = datetime(2024, 11, 14, 22, 0, tzinfo=timezone.utc)
    return [
        _get("prod-customer-data", f"trickle/{i}.csv", t=t0 + timedelta(minutes=i * 45), out=2_000_000)
        for i in range(12)
    ]


def scenario_malformed_event() -> list[dict]:
    """8. malformed events: one missing eventTime, one missing eventName."""
    bad_time = {
        **NORM,
        "eventID": _event_id(),
        "eventName": "GetObject",
        "requestParameters": {"bucketName": "prod-customer-data", "key": "a.csv"},
    }
    bad_time.pop("eventTime")
    bad_name = {
        **NORM,
        "eventID": _event_id(),
        "eventTime": "2024-11-14T03:00:00Z",
        "requestParameters": {"bucketName": "prod-customer-data", "key": "b.csv"},
    }
    return [bad_time, bad_name]


def scenario_incomplete_telemetry() -> list[dict]:
    """9. incomplete telemetry: from missing.py (no bytes, no UA, no IP)."""
    from .missing import ALL

    return ALL


def scenario_mixed_missing_destination(flow_reader) -> tuple[list[dict], list]:
    """10. mixed telemetry: some events have matching flows, some do not;
    destination known for a subset only."""
    t0 = datetime(2024, 11, 14, 7, 0, tzinfo=timezone.utc)
    events = [_get("prod-customer-data", f"mixed/{i}.csv", t=t0 + timedelta(seconds=i * 40), out=10_000_000)
              for i in range(6)]
    # flows only for the first three events
    flows = []
    for i in range(3):
        start = t0 + timedelta(seconds=i * 40 + 5)
        flows.append({
            "version": 2,
            "interface-id": "eni-0abc1234",
            "account-id": "111122223333",
            "region": "us-east-1",
            "src-addr": "10.0.1.20",
            "dst-addr": "198.51.100.77",
            "start": int(start.timestamp()),
            "end": int((start + timedelta(seconds=30)).timestamp()),
            "protocol": 6,
            "bytes": 11_000_000,
            "packets": 9_000,
            "type": "IPv4",
        })
    return events, flows


def scenario_backup_events_for_baseline() -> list[dict]:
    """Two weeks of nightly backups to train resource-profile history."""
    rng = random.Random(1234)
    events: list[dict] = []
    base_day = datetime(2024, 10, 1, 1, 0, tzinfo=timezone.utc)
    for day in range(14):
        t0 = base_day + timedelta(days=day)
        for i in range(6):
            rec = _get("backups-prod", f"nightly/d{day}-part-{i}.tar",
                       t=t0 + timedelta(minutes=i * 4), out=500_000_000 + rng.randint(-50_000_000, 50_000_000))
            rec["arn"] = "arn:aws:sts::111122223333:assumed-role/BackupOperator/backup-job-42"
            rec["type"] = "AssumedRole"
            rec["userAgent"] = "aws-sdk-go/1.44 (backup-agent)"
            events.append(rec)
    return events
