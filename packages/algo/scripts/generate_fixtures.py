"""Generate synthetic/replay fixtures for the Cloud Destructive Activity Detector.

Writes, per scenario (13 total), under
``detection/cloud_destruction/tests/fixtures/synthetic/<scenario>/``:

- ``raw.json``        provider-shaped records (CloudTrail / EventBridge)
- ``events.jsonl``    canonical :class:`ResourceActivityEvent` payloads
- plus a top-level ``manifest.json`` with per-scenario counts

Replay corpora land under ``fixtures/replay/``.

Everything is deterministic (fixed base time, no randomness). All destructive
behaviour is *simulated telemetry only* — nothing here touches real cloud
resources. Run: ``python scripts/generate_fixtures.py``.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.cloud_destruction.normalizer import ResourceActivityNormalizer  # noqa: E402
from detection.cloud_destruction.exceptions import UnsupportedEventError  # noqa: E402
from ingestion.aws.snapshot_events import normalize_snapshot_service_event  # noqa: E402
from ingestion.aws.backup_events import normalize_backup_service_event  # noqa: E402

FIXTURES = ROOT / "detection" / "cloud_destruction" / "tests" / "fixtures"
SYNTH = FIXTURES / "synthetic"
REPLAY = FIXTURES / "replay"

BASE = datetime(2026, 9, 1, tzinfo=timezone.utc)


def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Identities and resources (shared, deterministic)
# --------------------------------------------------------------------------- #

ACCOUNT = "111122223333"
REGION = "us-east-1"

ALICE = {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/alice.admin", "userName": "alice.admin", "ip": "198.51.100.24", "ua": "aws-console/Mozilla"}
BACKUP_PLANNER = {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/backup-planner/scheduled-job-1", "session": "backup-planner", "ip": "10.20.30.40", "ua": "aws-sdk-python/1.34.0"}
LIFECYCLE_MANAGER = {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/lifecycle-manager/scheduled-job-7", "session": "lifecycle-manager", "ip": "10.20.30.41", "ua": "aws-sdk-python/1.34.0"}
ATTACKER = {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/devops-contractor/compromised-session", "session": "devops-contractor", "ip": "203.0.113.66", "ua": "aws-cli/2.15.0"}

BUCKET_ARCHIVE = "fin-prod-archive"          # versioned + object lock, critical
BUCKET_REPORTS = "fin-prod-reports"          # backup enabled, critical
BUCKET_LOGS = "ops-app-logs"                 # unclassified lifecycle cleanup
VOL_DB = "vol-0abc1234db"                    # critical volume
SNAP_PREFIX = "snap-0db"
RDS_SNAP_PREFIX = "snap-0rdsfin"
VAULT_MAIN = "fin-prod-vault"
VAULT_SECOND = "fin-prod-vault-legacy"


def user_identity(actor: dict) -> dict:
    identity: dict = {"type": actor["type"], "arn": actor["arn"], "accountId": ACCOUNT}
    if actor["type"] == "IAMUser":
        identity["userName"] = actor["userName"]
    else:
        identity["principalId"] = f"AROAJEXAMPLE:{actor['session']}"
        identity["sessionContext"] = {
            "sessionIssuer": {"type": "Role", "arn": f"arn:aws:iam::{ACCOUNT}:role/{actor['session']}", "userName": actor["session"]},
        }
    return identity


_seq = 100000


def ct_event(
    dt: datetime,
    event_source: str,
    event_name: str,
    actor: dict,
    params: dict | None = None,
    resources: list | None = None,
    *,
    event_id: str | None = None,
    region: str = REGION,
    account: str = ACCOUNT,
    response: dict | None = None,
    error_code: str | None = None,
) -> dict:
    global _seq
    _seq += 1
    record = {
        "eventVersion": "1.09",
        "eventID": event_id or f"synthetic-{_seq:08d}",
        "eventTime": ts(dt),
        "eventSource": f"{event_source}.amazonaws.com",
        "eventName": event_name,
        "awsRegion": region,
        "recipientAccountId": account,
        "sourceIPAddress": actor["ip"],
        "userAgent": actor["ua"],
        "userIdentity": user_identity(actor),
        "requestParameters": params or {},
        "eventCategory": "Data" if event_source == "s3" and params else "Management",
    }
    if resources:
        record["resources"] = resources
    if response:
        record["responseElements"] = response
    if error_code:
        record["errorCode"] = error_code
        record["errorMessage"] = "synthetic error for fixture replay"
    return record


def s3_arn(bucket: str, key: str | None = None) -> dict:
    arn = f"arn:aws:s3:::{bucket}" + (f"/{key}" if key else "")
    return {"ARN": arn, "accountId": ACCOUNT}


def eb_event(event_id: str, dt: datetime, source: str, detail_type: str, detail: dict, region: str = REGION) -> dict:
    return {
        "version": "0",
        "id": event_id,
        "detail-type": detail_type,
        "source": source,
        "account": ACCOUNT,
        "time": ts(dt),
        "region": region,
        "resources": [],
        "detail": detail,
    }


# --------------------------------------------------------------------------- #
# Scenario builders — each returns (name, description, raw records)
# --------------------------------------------------------------------------- #


def normal_writes() -> tuple[str, str, list[dict]]:
    """20 days of routine PutObject activity by a human administrator."""
    records = []
    for day in range(20):
        for n in range(3):
            dt = BASE + timedelta(days=day, hours=9 + n, minutes=7 * n)
            key = f"reports/2026/09/day-{day:02d}-batch-{n}.json"
            records.append(
                ct_event(
                    dt, "s3", "PutObject", ALICE,
                    {"bucketName": BUCKET_REPORTS, "key": key},
                    [s3_arn(BUCKET_REPORTS, key)],
                )
            )
    return "normal_writes", "Routine daily uploads by a human administrator over 20 days", records


def normal_lifecycle_cleanup() -> tuple[str, str, list[dict]]:
    """Scheduled 02:00 noncurrent-object cleanup by the lifecycle role."""
    records = []
    for day in range(10):
        for n in range(5):
            dt = BASE + timedelta(days=day, hours=2, minutes=n * 3)
            key = f"logs/app/{day:02d}/chunk-{n}.log"
            records.append(
                ct_event(
                    dt, "s3", "DeleteObject", LIFECYCLE_MANAGER,
                    {"bucketName": BUCKET_LOGS, "key": key},
                    [s3_arn(BUCKET_LOGS, key)],
                    response={"x-amz-delete-marker": "true"},
                )
            )
    return "normal_lifecycle_cleanup", "Steady scheduled lifecycle deletion at 02:00 by an automation role", records


def scheduled_backup_cleanup() -> tuple[str, str, list[dict]]:
    """Backup planner deletes expired recovery points on schedule at 03:00."""
    records = []
    for day in range(10):
        for n in range(4):
            dt = BASE + timedelta(days=day, hours=3, minutes=n * 11)
            rp = f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}/recovery-point/regular-{day:02d}{n}"
            records.append(
                ct_event(
                    dt, "backup", "DeleteRecoveryPoint", BACKUP_PLANNER,
                    {"BackupVaultName": VAULT_MAIN, "RecoveryPointArn": rp},
                    [{"ARN": rp}],
                )
            )
    return "scheduled_backup_cleanup", "Scheduled expiry deletion of recovery points by the backup automation role", records


def mass_modification() -> tuple[str, str, list[dict]]:
    """Attacker rewrites many existing objects with new tags/metadata."""
    records = []
    for i in range(40):
        dt = BASE + timedelta(minutes=2 * i)
        key = f"reports/2026/08/summary-{i:03d}.csv"
        records.append(
            ct_event(
                dt, "s3", "CopyObject", ATTACKER,
                {"bucketName": BUCKET_REPORTS, "key": key, "copySource": f"{BUCKET_REPORTS}/{key}"},
                [s3_arn(BUCKET_REPORTS, key)],
            )
        )
    return "mass_modification", "Burst modification of 40 existing objects within 80 minutes", records


def mass_deletion() -> tuple[str, str, list[dict]]:
    """Attacker issues batched multi-object deletes across several buckets."""
    records = []
    buckets = [BUCKET_REPORTS, BUCKET_ARCHIVE, BUCKET_LOGS]
    for batch in range(4):
        dt = BASE + timedelta(minutes=7 * batch)
        objects = [
            {"Key": f"batch-delete/{batch:02d}/obj-{i:03d}.bin"} for i in range(20)
        ]
        bucket = buckets[batch % len(buckets)]
        records.append(
            ct_event(
                dt, "s3", "DeleteObjects", ATTACKER,
                {"bucketName": bucket, "Delete": {"Objects": objects}},
                [s3_arn(bucket)],
            )
        )
    return "mass_deletion", "Four batched DeleteObjects calls removing 80 objects across 3 buckets", records


def version_deletion() -> tuple[str, str, list[dict]]:
    """Attacker deletes object versions (and markers) on a versioned bucket."""
    records = []
    for i in range(60):
        dt = BASE + timedelta(seconds=15 * i)
        key = f"archive/ledger/{i % 12:02d}.pq"
        if i % 6 == 5:
            params = {"bucketName": BUCKET_ARCHIVE, "key": key}
            response = {"x-amz-delete-marker": "true", "x-amz-version-id": "marker.."}
        else:
            params = {"bucketName": BUCKET_ARCHIVE, "key": key, "versionId": f"vId-{i:06d}abc"}
            response = None
        records.append(
            ct_event(
                dt, "s3", "DeleteObjectVersion" if "versionId" in params else "DeleteObject",
                ATTACKER, params, [s3_arn(BUCKET_ARCHIVE, key)], response=response,
            )
        )
    return "version_deletion", "Versioned-bucket scrubbing: 60 version deletions in 15 minutes", records


def snapshot_deletion() -> tuple[str, str, list[dict]]:
    """Attacker deletes EBS snapshots of a critical volume across regions."""
    records = []
    for i in range(12):
        dt = BASE + timedelta(minutes=5 * i)
        region = REGION if i % 2 == 0 else "eu-west-1"
        snap = f"{SNAP_PREFIX}{i:03d}"
        arn = f"arn:aws:ec2:{region}:{ACCOUNT}:snapshot/{snap}"
        records.append(
            ct_event(
                dt, "ec2", "DeleteSnapshot", ATTACKER,
                {"SnapshotId": snap}, [{"ARN": arn}], region=region,
            )
        )
    return "snapshot_deletion", "12 EBS snapshot deletions across 2 regions within an hour", records


def recovery_point_deletion() -> tuple[str, str, list[dict]]:
    """Attacker deletes recovery points from two backup vaults."""
    records = []
    for i in range(10):
        dt = BASE + timedelta(minutes=3 * i)
        vault = VAULT_MAIN if i % 3 else VAULT_SECOND
        rp = f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{vault}/recovery-point/rp-{i:04d}"
        records.append(
            ct_event(
                dt, "backup", "DeleteRecoveryPoint", ATTACKER,
                {"BackupVaultName": vault, "RecoveryPointArn": rp}, [{"ARN": rp}],
            )
        )
    return "recovery_point_deletion", "Recovery-point deletion across two vaults within 30 minutes", records


def recovery_protection_change() -> tuple[str, str, list[dict]]:
    """Attacker degrades protection: versioning suspension, lock/lifecycle removal."""
    records: list[dict] = []
    dt = BASE
    for i in range(3):
        dt = dt + timedelta(minutes=4)
        records.append(
            ct_event(
                dt, "s3", "PutBucketVersioning", ATTACKER,
                {"bucketName": BUCKET_ARCHIVE, "VersioningConfiguration": {"Status": "Suspended"}},
                [s3_arn(BUCKET_ARCHIVE)],
            )
        )
    for i in range(2):
        dt = dt + timedelta(minutes=4)
        records.append(
            ct_event(dt, "s3", "DeleteBucketLifecycleConfiguration", ATTACKER,
                     {"bucketName": BUCKET_ARCHIVE}, [s3_arn(BUCKET_ARCHIVE)])
        )
    for i in range(2):
        dt = dt + timedelta(minutes=4)
        records.append(
            ct_event(dt, "s3", "PutBucketObjectLockConfiguration", ATTACKER,
                     {"bucketName": BUCKET_ARCHIVE,
                      "ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}},
                     [s3_arn(BUCKET_ARCHIVE)])
        )
    for i in range(2):
        dt = dt + timedelta(minutes=4)
        records.append(
            ct_event(dt, "backup", "DeleteBackupVaultLockConfiguration", ATTACKER,
                     {"BackupVaultName": VAULT_MAIN}, [{"ARN": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}"}])
        )
    for i in range(2):
        dt = dt + timedelta(minutes=4)
        records.append(
            ct_event(dt, "s3", "DeleteBucketPolicy", ATTACKER,
                     {"bucketName": BUCKET_REPORTS}, [s3_arn(BUCKET_REPORTS)])
        )
    dt = dt + timedelta(minutes=4)
    records.append(
        ct_event(dt, "backup", "DeleteBackupVaultAccessPolicy", ATTACKER,
                 {"BackupVaultName": VAULT_SECOND},
                 [{"ARN": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_SECOND}"}])
    )
    dt = dt + timedelta(minutes=4)
    records.append(
        ct_event(dt, "backup", "UpdateRecoveryPointLifecycle", ATTACKER,
                 {"BackupVaultName": VAULT_MAIN,
                  "RecoveryPointArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}/recovery-point/rp-lifecycle",
                  "Lifecycle": {"DeleteAfterDays": 1}},
                 [{"ARN": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}/recovery-point/rp-lifecycle"}])
    )
    dt = dt + timedelta(minutes=4)
    records.append(
        ct_event(dt, "backup", "PutBackupVaultLockConfiguration", ATTACKER,
                 {"BackupVaultName": VAULT_SECOND, "RetentionPeriod": {"Days": 0}},
                 [{"ARN": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_SECOND}"}])
    )
    dt = dt + timedelta(minutes=4)
    records.append(
        ct_event(dt, "s3", "PutBucketAcl", ATTACKER,
                 {"bucketName": BUCKET_LOGS, "AccessControlPolicy": {"Owner": {}, "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}},
                 [s3_arn(BUCKET_LOGS)])
    )
    dt = dt + timedelta(minutes=4)
    records.append(
        ct_event(dt, "backup", "DeleteBackupVault", ATTACKER,
                 {"BackupVaultName": VAULT_SECOND},
                 [{"ARN": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_SECOND}"}])
    )
    return "recovery_protection_change", "16 protection-degrading actions across buckets and backup vaults", records


def mass_rewrite_sequence() -> tuple[str, str, list[dict]]:
    """Attacker rewrites 70 objects in place — ransomware-style replacement."""
    records = []
    for i in range(70):
        dt = BASE + timedelta(seconds=17 * i)
        key = f"archive/data/{i:03d}.enc"
        records.append(
            ct_event(
                dt, "s3", "CopyObject", ATTACKER,
                {"bucketName": BUCKET_ARCHIVE, "key": key,
                 "copySource": f"{BUCKET_ARCHIVE}/archive/data/{i:03d}.dat",
                 "ServerSideEncryption": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "rekeyed"}},
                [s3_arn(BUCKET_ARCHIVE, key)],
            )
        )
    return "mass_rewrite_sequence", "70 same-prefix rewrites with new encryption keys in 20 minutes", records


def mixed_normal_destructive() -> tuple[str, str, list[dict]]:
    """Normal writes + scheduled cleanup first, then a destructive burst."""
    records: list[dict] = []
    _, _, normal = normal_writes()
    records.extend(normal[:30])
    _, _, cleanup = scheduled_backup_cleanup()
    records.extend(cleanup[:20])
    _, _, destructive = mass_deletion()
    shifted = []
    for record in destructive:
        shifted.append(record)
    records.extend(shifted)
    return "mixed_normal_destructive", "Routine activity followed by a destructive burst (overlapping actors)", records


def malformed_telemetry() -> tuple[str, str, list[dict]]:
    """Structurally broken records that must be quarantined, never normalized."""
    # Each record violates one distinct required field / structural rule.
    broken: list[dict] = [
        {"note": "not a cloudtrail record at all"},        # 0: no eventID/timestamp
        {"eventVersion": "1.09", "eventTime": ts(BASE)},   # 1: missing eventName
        {"eventVersion": "1.09", "eventName": "DeleteObject"},  # 2: missing eventTime
        {"eventName": "DeleteObject", "eventTime": "not-a-timestamp", "eventID": "malformed-001"},  # 3: bad timestamp
        {"eventVersion": "2.99", "eventName": "DeleteObject", "eventTime": ts(BASE), "eventID": "malformed-002"},  # 4: unsupported schema version
        {**ct_event(BASE, "s3", "DeleteObject", ATTACKER), "eventID": ""},  # 5: empty eventID
        {"eventVersion": "1.09", "eventName": 12345, "eventTime": ts(BASE), "eventID": "malformed-003"},  # 6: eventName not a string
        {"eventVersion": "1.09", "eventName": "DeleteObject", "eventTime": 99999999999999.9, "eventID": "malformed-004"},  # 7: timestamp out of range
        [],                                                # 8: not even a dict
        {"eventVersion": "1.09", "eventName": "DeleteObject", "eventTime": None, "eventID": "malformed-005"},  # 9: null timestamp
        {**ct_event(BASE + timedelta(minutes=1), "s3", "DeleteObject", ATTACKER, event_id="malformed-006"), "userIdentity": "not-a-dict"},  # 10: wrong identity type
    ]
    return "malformed_telemetry", "Malformed records: missing/invalid required fields and wrong types", broken


def missing_telemetry_fields() -> tuple[str, str, list[dict]]:
    """Valid but sparse records: optional fields absent, availability recorded."""
    records = [
        {"eventVersion": "1.09", "eventID": "sparse-001", "eventTime": ts(BASE),
         "eventSource": "s3.amazonaws.com", "eventName": "DeleteObject",
         "requestParameters": {"bucketName": BUCKET_LOGS, "key": "logs/gap-001.log"}},
        {"eventVersion": "1.09", "eventID": "sparse-002", "eventTime": ts(BASE + timedelta(minutes=1)),
         "eventSource": "s3.amazonaws.com", "eventName": "PutObject",
         "recipientAccountId": ACCOUNT,
         "requestParameters": {"bucketName": BUCKET_REPORTS, "key": "reports/sparse-002.json"}},
        {"eventVersion": "1.09", "eventID": "sparse-003", "eventTime": ts(BASE + timedelta(minutes=2)),
         "eventSource": "ec2.amazonaws.com", "eventName": "DeleteSnapshot",
         "awsRegion": REGION, "recipientAccountId": ACCOUNT,
         "requestParameters": {"SnapshotId": f"{SNAP_PREFIX}900"}},
        {"eventVersion": "1.09", "eventID": "sparse-004", "eventTime": ts(BASE + timedelta(minutes=3)),
         "eventSource": "backup.amazonaws.com", "eventName": "DeleteRecoveryPoint",
         "awsRegion": REGION,
         "requestParameters": {"BackupVaultName": VAULT_MAIN}},
        {"eventVersion": "1.09", "eventID": "sparse-005", "eventTime": ts(BASE + timedelta(minutes=4)),
         "eventSource": "s3.amazonaws.com", "eventName": "DeleteObjects",
         "requestParameters": {"bucketName": BUCKET_LOGS}},
    ]
    return "missing_telemetry_fields", "Valid records with absent actor/region/account/network fields", records


# --------------------------------------------------------------------------- #
# EventBridge replay corpora
# --------------------------------------------------------------------------- #


def backup_eventbridge_replay() -> list[dict]:
    records = [
        eb_event("eb-backup-001", BASE + timedelta(hours=1), "aws.backup", "Backup Job State Change",
                 {"jobId": "job-001", "state": "COMPLETED",
                  "backupVaultArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}",
                  "recoveryPointArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}/recovery-point/nightly-001"}),
        eb_event("eb-backup-002", BASE + timedelta(hours=2), "aws.backup", "Backup Job State Change",
                 {"jobId": "job-002", "state": "EXPIRED",
                  "backupVaultArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}",
                  "recoveryPointArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}/recovery-point/nightly-002"}),
        eb_event("eb-backup-003", BASE + timedelta(hours=3), "aws.backup", "Restore Job State Change",
                 {"jobId": "job-003", "state": "COMPLETED",
                  "backupVaultArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}",
                  "recoveryPointArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}/recovery-point/nightly-003"}),
        eb_event("eb-backup-004", BASE + timedelta(hours=4), "aws.backup", "Copy Job State Change",
                 {"jobId": "job-004", "state": "COMPLETED",
                  "backupVaultArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}",
                  "recoveryPointArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_MAIN}/recovery-point/nightly-004"}),
        eb_event("eb-backup-005", BASE + timedelta(hours=5), "aws.backup", "Backup Job State Change",
                 {"jobId": "job-005", "state": "DELETE_COMPLETED",
                  "backupVaultArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_SECOND}",
                  "recoveryPointArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:{VAULT_SECOND}/recovery-point/nightly-005"}),
    ]
    return records


def snapshot_eventbridge_replay() -> list[dict]:
    return [
        eb_event("eb-snap-001", BASE + timedelta(hours=1), "aws.ec2", "EC2 Snapshot Create",
                 {"source": f"{SNAP_PREFIX}101", "state": "completed"}),
        eb_event("eb-snap-002", BASE + timedelta(hours=2), "aws.ec2", "EC2 Snapshot Delete",
                 {"source": f"{SNAP_PREFIX}102", "state": "deleted"}),
        eb_event("eb-snap-003", BASE + timedelta(hours=3), "aws.ec2", "EC2 Snapshot Copy",
                 {"source": f"{SNAP_PREFIX}103", "state": "completed"}),
        eb_event("eb-rds-001", BASE + timedelta(hours=4), "aws.rds", "RDS DB Snapshot Event",
                 {"SourceIdentifier": f"{RDS_SNAP_PREFIX}001", "EventID": "RDS-EVENT-0058", "Message": "Manual snapshot deleted"}),
        eb_event("eb-rds-002", BASE + timedelta(hours=5), "aws.rds", "RDS DB Snapshot Event",
                 {"SourceIdentifier": f"{RDS_SNAP_PREFIX}002", "EventID": "RDS-EVENT-0070", "Message": "Snapshot created"}),
    ]


# --------------------------------------------------------------------------- #
# Canonical projection + writers
# --------------------------------------------------------------------------- #

_NORMALIZER = ResourceActivityNormalizer()


def canonical_for(raw_records: list[dict]) -> list[dict]:
    """Best-effort canonical projection of raw records (unsupported skipped)."""
    events: list[dict] = []
    for index, record in enumerate(raw_records):
        try:
            if record.get("detail-type") == "RDS DB Snapshot Event" or str(record.get("detail-type", "")).startswith("EC2 Snapshot"):
                event = normalize_snapshot_service_event(record, is_replayed=True, is_synthetic=True, generator="fixtures")
            elif record.get("detail-type"):
                event = normalize_backup_service_event(record, is_replayed=True, is_synthetic=True, generator="fixtures")
            else:
                event = _NORMALIZER.normalize_cloudtrail(
                    record, raw_event_reference=f"cloudtrail://{record.get('eventID', index)}",
                    raw_record_index=index, is_replayed=True, is_synthetic=True, generator="fixtures",
                )
        except UnsupportedEventError:
            continue
        except Exception:
            continue
        events.append(json.loads(event.model_dump_json()))
    return events


def write_scenario(name: str, description: str, records: list[dict]) -> dict:
    out_dir = SYNTH / name
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "raw.json").write_text(
        json.dumps({"scenario": name, "description": description, "records": records}, indent=2),
        encoding="utf-8",
    )
    events = canonical_for(records)
    with (out_dir / "events.jsonl").open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
    return {"scenario": name, "description": description, "raw_records": len(records), "canonical_events": len(events)}


def main() -> int:
    builders = [
        normal_writes,
        normal_lifecycle_cleanup,
        scheduled_backup_cleanup,
        mass_modification,
        mass_deletion,
        version_deletion,
        snapshot_deletion,
        recovery_point_deletion,
        recovery_protection_change,
        mass_rewrite_sequence,
        mixed_normal_destructive,
        malformed_telemetry,
        missing_telemetry_fields,
    ]
    manifest: dict[str, object] = {"base_time": ts(BASE), "scenarios": []}
    for builder in builders:
        name, description, records = builder()
        entry = write_scenario(name, description, records)
        manifest["scenarios"].append(entry)  # type: ignore[union-attr]
        print(f"  {name:32s} raw={entry['raw_records']:4d} canonical={entry['canonical_events']:4d}")

    REPLAY.mkdir(parents=True, exist_ok=True)
    (REPLAY / "backup_eventbridge_sample.json").write_text(
        json.dumps({"records": backup_eventbridge_replay()}, indent=2), encoding="utf-8"
    )
    (REPLAY / "snapshot_eventbridge_sample.json").write_text(
        json.dumps({"records": snapshot_eventbridge_replay()}, indent=2), encoding="utf-8"
    )
    (SYNTH / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("fixtures written under", SYNTH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
