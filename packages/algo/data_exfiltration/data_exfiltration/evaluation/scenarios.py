"""Canonical evaluation scenario generators (SYNTHETIC — labeled as such).

Fifteen scenario families required by the Algorithm #2 contract. Each
generator returns a list of CloudTrail-shaped dicts (+ optional VPC flow
dicts). All timestamps are deterministic: derived from a fixed base, no
wall clock. Ground truth labels: benign=0, exfiltration=1.

These fixtures exist to measure relative variant behavior. Metrics
computed over them describe THIS fixture only and must never be
presented as real-world performance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from algo.data_exfiltration.data_exfiltration.tests.fixtures.cloudtrail_records import NORM

BASE_TS = datetime(2025, 1, 6, 0, 0, tzinfo=timezone.utc)  # a Monday
_SEQ = iter(range(10_000))

ANALYST_ARN = "arn:aws:iam::111122223333:user/data-analyst"
BACKUP_ROLE = "arn:aws:sts::111122223333:assumed-role/BackupOperator/backup-job-7"
ETL_ROLE = "arn:aws:sts::111122223333:assumed-role/ETLWorker/etl-run-3"
MIGRATION_ROLE = "arn:aws:sts::111122223333:assumed-role/MigrationCrew/mig-9"
INSIDER_ARN = "arn:aws:iam::111122223333:user/support-agent"

SENSITIVE_BUCKET = "prod-customer-data"
BACKUP_BUCKET = "backups-prod"
WAREHOUSE_BUCKET = "dw-exports"
PUBLIC_BUCKET = "public-site-assets"
ATTACKER_BUCKET = "attacker-staging"


def _event_id() -> str:
    n = next(_SEQ)
    return f"eeeeeeee-7000-4000-8000-{n:012d}"


@dataclass
class ScenarioBundle:
    """One scenario instance: telemetry + ground truth + metadata."""

    name: str
    """Family name, e.g. ``normal_user``."""
    instance: int
    label: int
    """1 = exfiltration, 0 = benign."""
    cloudtrail: list[dict] = field(default_factory=list)
    flows: list[dict] = field(default_factory=list)
    synthetic: bool = True
    description: str = ""

    @property
    def scenario_id(self) -> str:
        return f"{self.name}-{self.instance:03d}"


def _get(
    bucket: str,
    key: str,
    *,
    t: datetime,
    out: int,
    arn: str = ANALYST_ARN,
    ip: str | None = "203.0.113.10",
    ua: str | None = "aws-sdk-python/1.34.0",
    role: bool = False,
) -> dict:
    rec = {
        **NORM,
        "eventID": _event_id(),
        "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": "GetObject",
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": {"bucketName": bucket, "key": key},
        "additionalEventData": {"bytesTransferredOut": out},
        "arn": arn,
        "type": "AssumedRole" if role else "IAMUser",
    }
    if role:
        rec["principalId"] = "AROAAAAAAAAAAAAAAAAAA:job"
    return rec


def _flow(t: datetime, *, dst: str = "198.51.100.77", src: str = "10.0.1.20", nbytes: int = 80_000_000) -> dict:
    return {
        "version": 2,
        "interface-id": "eni-0abc1234",
        "account-id": "111122223333",
        "region": "us-east-1",
        "src-addr": src,
        "dst-addr": dst,
        "start": int(t.timestamp()),
        "end": int((t + timedelta(seconds=30)).timestamp()),
        "protocol": 6,
        "bytes": nbytes,
        "packets": max(1, nbytes // 1400),
        "type": "IPv4",
    }


# ---------------------------------------------------------------------------
# benign scenarios (label 0)
# ---------------------------------------------------------------------------


def normal_user(i: int) -> ScenarioBundle:
    """1. normal user: a few small reads, business hours, known bucket."""
    t0 = BASE_TS + timedelta(days=i, hours=10 + (i % 6))
    return ScenarioBundle(
        name="normal_user",
        instance=i,
        label=0,
        description="small routine reads, business hours",
        cloudtrail=[
            _get("app-assets", f"img/{k}.png", t=t0 + timedelta(seconds=k * 20), out=25_000)
            for k in range(4)
        ],
    )


def normal_backup(i: int) -> ScenarioBundle:
    """2. normal backup: big volume, dedicated role, nightly window, one bucket."""
    t0 = BASE_TS + timedelta(days=i, hours=1)
    return ScenarioBundle(
        name="normal_backup",
        instance=i,
        label=0,
        description="large nightly backup by dedicated role in approved window",
        cloudtrail=[
            _get(BACKUP_BUCKET, f"nightly/d{i}-part-{k}.tar", t=t0 + timedelta(minutes=k * 4),
                 out=500_000_000, arn=BACKUP_ROLE, ua="aws-sdk-go/1.44 (backup-agent)", role=True)
            for k in range(6)
        ],
    )


def scheduled_etl(i: int) -> ScenarioBundle:
    """3. scheduled ETL: warehouse role reads business data on schedule."""
    t0 = BASE_TS + timedelta(days=i, hours=2)
    return ScenarioBundle(
        name="scheduled_etl",
        instance=i,
        label=0,
        description="scheduled warehouse extract by ETL role",
        cloudtrail=[
            _get(WAREHOUSE_BUCKET, f"extract/{i}/part-{k}.parquet", t=t0 + timedelta(minutes=k * 3),
                 out=120_000_000, arn=ETL_ROLE, ua="aws-sdk-java/2.20 (etl-worker)", role=True)
            for k in range(5)
        ],
    )


def legitimate_migration(i: int) -> ScenarioBundle:
    """4. legitimate migration: migration crew copies between known buckets."""
    t0 = BASE_TS + timedelta(days=i, hours=9)
    recs = []
    for k in range(5):
        rec = _get("legacy-archive", f"cold/{i}/obj-{k}.zip", t=t0 + timedelta(minutes=k * 6),
                   out=200_000_000, arn=MIGRATION_ROLE, ua="aws-cli/2.13 (migration)", role=True)
        recs.append(rec)
    return ScenarioBundle(
        name="legitimate_migration",
        instance=i,
        label=0,
        description="approved migration crew, known buckets, business hours",
        cloudtrail=recs,
    )


def large_public_transfer(i: int) -> ScenarioBundle:
    """5. large public-data transfer: big bytes, zero sensitivity."""
    t0 = BASE_TS + timedelta(days=i, hours=15)
    return ScenarioBundle(
        name="large_public_transfer",
        instance=i,
        label=0,
        description="high volume but public content via CDN edges",
        cloudtrail=[
            _get(PUBLIC_BUCKET, f"media/video-{i}-{k}.mp4", t=t0 + timedelta(seconds=k * 15),
                 out=400_000_000, ua="CloudFront")
            for k in range(6)
        ],
    )


def travel_access(i: int) -> ScenarioBundle:
    """14. legitimate travel + data access: same actor, same behavior,
    from a travel location; telemetry noise, not exfiltration."""
    t0 = BASE_TS + timedelta(days=i, hours=8)
    recs = [
        _get("app-assets", f"reports/{k}.pdf", t=t0 + timedelta(seconds=k * 30), out=2_000_000)
        for k in range(4)
    ]
    for r in recs:
        r["sourceIPAddress"] = "198.51.100.201"  # hotel exit IP (novel location)
        r["userAgent"] = "aws-sdk-python/1.34.0"  # unchanged tooling
    flows = [_flow(t0 + timedelta(seconds=k * 30 + 5), dst="198.51.100.201", nbytes=2_100_000) for k in range(4)]
    return ScenarioBundle(
        name="legitimate_travel",
        instance=i,
        label=0,
        description="novel source location, ordinary access pattern and volume",
        cloudtrail=recs,
        flows=flows,
    )


# ---------------------------------------------------------------------------
# exfiltration scenarios (label 1)
# ---------------------------------------------------------------------------


def sensitive_transfer(i: int) -> ScenarioBundle:
    """6. sensitive-data transfer: sensitive bucket, sizable reads."""
    t0 = BASE_TS + timedelta(days=i, hours=3)
    return ScenarioBundle(
        name="sensitive_transfer",
        instance=i,
        label=1,
        description="large reads from sensitive bucket at odd hour",
        cloudtrail=[
            _get(SENSITIVE_BUCKET, f"pii/customers-eu-{i}.csv", t=t0 + timedelta(seconds=k * 40),
                 out=60_000_000)
            for k in range(5)
        ],
    )


def new_destination(i: int) -> ScenarioBundle:
    """7. new destination: copy toward a never-seen external target."""
    t0 = BASE_TS + timedelta(days=i, hours=4)
    rec = {
        **NORM,
        "eventID": _event_id(),
        "eventTime": t0.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": "CopyObject",
        "requestParameters": {
            "bucketName": ATTACKER_BUCKET,
            "key": f"stash/customers-{i}.csv",
            "x-amz-copy-source": f"{SENSITIVE_BUCKET}/pii/customers-eu.csv",
        },
        "additionalEventData": {"bytesTransferredOut": 90_000_000},
        "arn": INSIDER_ARN,
        "type": "IAMUser",
    }
    return ScenarioBundle(
        name="new_destination",
        instance=i,
        label=1,
        description="copy of sensitive object to unseen external bucket",
        cloudtrail=[rec],
    )


def unusual_sequence(i: int) -> ScenarioBundle:
    """8. unusual access sequence: enumerate-then-exfiltrate pattern."""
    t0 = BASE_TS + timedelta(days=i, hours=2)
    recs = [
        {
            **NORM,
            "eventID": _event_id(),
            "eventTime": (t0 + timedelta(seconds=j * 2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventName": "ListObjectsV2",
            "requestParameters": {"bucketName": SENSITIVE_BUCKET, "prefix": f"p{j}/", "maxResults": 1000},
            "responseElements": {"isTruncated": "true"},
            "additionalEventData": None,
        }
        for j in range(20)
    ]
    recs += [
        _get(SENSITIVE_BUCKET, f"pii/dump-{i}-{k}.csv", t=t0 + timedelta(minutes=2, seconds=k * 10),
             out=30_000_000)
        for k in range(4)
    ]
    return ScenarioBundle(
        name="unusual_sequence",
        instance=i,
        label=1,
        description="rapid enumeration followed by bulk sensitive reads",
        cloudtrail=recs,
    )


def large_external_egress(i: int) -> ScenarioBundle:
    """9. large external egress: reads + matching flows to one external IP."""
    t0 = BASE_TS + timedelta(days=i, hours=5)
    recs = [
        _get(SENSITIVE_BUCKET, f"dump/{i}-{k}.csv", t=t0 + timedelta(seconds=k * 30), out=80_000_000)
        for k in range(5)
    ]
    flows = [
        _flow(t0 + timedelta(seconds=k * 30 + 5), dst=f"198.51.100.{77 + (i % 16)}", nbytes=82_000_000)
        for k in range(5)
    ]
    return ScenarioBundle(
        name="large_external_egress",
        instance=i,
        label=1,
        description="network evidence corroborates bulk movement to one external IP",
        cloudtrail=recs,
        flows=flows,
    )


def slow_exfiltration(i: int) -> ScenarioBundle:
    """10. slow exfiltration: small steady reads stretched over many hours."""
    t0 = BASE_TS + timedelta(days=i, hours=23)
    return ScenarioBundle(
        name="slow_exfiltration",
        instance=i,
        label=1,
        description="low-and-slow trickle under volume radar",
        cloudtrail=[
            _get(SENSITIVE_BUCKET, f"trickle/{i}-{k}.csv",
                 t=t0 + timedelta(days=(k * 40) // 1440, minutes=(k * 40) % 60),
                 out=2_000_000)
            for k in range(12)
        ],
    )


def burst_exfiltration(i: int) -> ScenarioBundle:
    """11. burst exfiltration: very high rate inside a short window."""
    t0 = BASE_TS + timedelta(days=i, hours=3, minutes=30)
    return ScenarioBundle(
        name="burst_exfiltration",
        instance=i,
        label=1,
        description="short, violent burst of large reads",
        cloudtrail=[
            _get(SENSITIVE_BUCKET, f"burst/{i}-{k}.csv", t=t0 + timedelta(seconds=k * 2),
                 out=150_000_000)
            for k in range(10)
        ],
    )


def missing_telemetry_exfil(i: int) -> ScenarioBundle:
    """12. missing telemetry: sparse records, but behavior still exfil-shaped."""
    t0 = BASE_TS + timedelta(days=i, hours=3)
    recs = []
    for k in range(5):
        rec = _get(SENSITIVE_BUCKET, f"sparse/{i}-{k}.csv", t=t0 + timedelta(seconds=k * 30),
                   out=40_000_000)
        if k % 2 == 0:
            rec["userAgent"] = None
        if k == 1:
            rec["sourceIPAddress"] = None
        recs.append(rec)
    return ScenarioBundle(
        name="missing_telemetry",
        instance=i,
        label=1,
        description="attacker benefits from sparse telemetry; signals remain",
        cloudtrail=recs,
    )


def misleading_high_volume(i: int) -> ScenarioBundle:
    """13. misleading high-volume activity: looks like a backup, is not.

    Big volume + backup-ish UA, BUT: wrong time, unusual actor, novel
    destination evidence, sensitive bucket. Label = exfiltration.
    """
    t0 = BASE_TS + timedelta(days=i, hours=14)  # mid-day, not backup window
    recs = [
        _get(SENSITIVE_BUCKET, f"nightly/part-{k}.tar", t=t0 + timedelta(minutes=k * 4),
             out=500_000_000, arn="arn:aws:sts::111122223333:assumed-role/BackupOperator/unknown-job",
             ua="aws-sdk-go/1.44 (backup-agent)", role=True)
        for k in range(6)
    ]
    flows = [
        _flow(t0 + timedelta(minutes=k * 4 + 5), dst="203.113.7.9", nbytes=510_000_000)
        for k in range(6)
    ]
    return ScenarioBundle(
        name="misleading_high_volume",
        instance=i,
        label=1,
        description="backup costume over exfiltration: wrong actor/time/target",
        cloudtrail=recs,
        flows=flows,
    )


def compromised_data_movement(i: int) -> ScenarioBundle:
    """15. compromised-data movement WITHOUT credential anomaly.

    A legitimate identity (no credential compromise anywhere) moves
    sensitive data at an unusual time toward an unseen destination.
    The credential axis is deliberately quiet; data behavior is not.
    """
    t0 = BASE_TS + timedelta(days=i, hours=3, minutes=15)
    recs = [
        _get(SENSITIVE_BUCKET, f"exfil/{i}-{k}.csv", t=t0 + timedelta(seconds=k * 25),
             out=70_000_000)
        for k in range(6)
    ]
    flows = [
        _flow(t0 + timedelta(seconds=k * 25 + 5), dst=f"198.51.100.{90 + (i % 8)}", nbytes=71_000_000)
        for k in range(6)
    ]
    return ScenarioBundle(
        name="compromised_data_movement",
        instance=i,
        label=1,
        description="legitimate identity, abnormal data movement only",
        cloudtrail=recs,
        flows=flows,
    )


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

BENIGN_GENERATORS = {
    "normal_user": normal_user,
    "normal_backup": normal_backup,
    "scheduled_etl": scheduled_etl,
    "legitimate_migration": legitimate_migration,
    "large_public_transfer": large_public_transfer,
    "travel_access": travel_access,
}

EXFIL_GENERATORS = {
    "sensitive_transfer": sensitive_transfer,
    "new_destination": new_destination,
    "unusual_sequence": unusual_sequence,
    "large_external_egress": large_external_egress,
    "slow_exfiltration": slow_exfiltration,
    "burst_exfiltration": burst_exfiltration,
    "missing_telemetry": missing_telemetry_exfil,
    "misleading_high_volume": misleading_high_volume,
    "compromised_data_movement": compromised_data_movement,
}

SCENARIO_GENERATORS = {**BENIGN_GENERATORS, **EXFIL_GENERATORS}

FIFTEEN_FAMILIES = [
    "normal_user", "normal_backup", "scheduled_etl", "legitimate_migration",
    "large_public_transfer", "sensitive_transfer", "new_destination",
    "unusual_sequence", "large_external_egress", "slow_exfiltration",
    "burst_exfiltration", "missing_telemetry", "misleading_high_volume",
    "travel_access", "compromised_data_movement",
]


def build_instances(per_family: int = 6) -> list[ScenarioBundle]:
    """Build the labeled corpus: all 15 families x N instances."""
    bundles: list[ScenarioBundle] = []
    for family in FIFTEEN_FAMILIES:
        gen = SCENARIO_GENERATORS[family]
        for i in range(per_family):
            bundles.append(gen(i))
    return bundles
