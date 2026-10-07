"""AWS ingestion module tests: CloudTrail batches + EventBridge streams."""

from __future__ import annotations

import pytest

from detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from detection.cloud_destruction.schemas import (
    ActionCategory,
    OperationType,
    ResourceType,
)
from ingestion.aws.backup_events import BackupEventIngestor, normalize_backup_service_event
from ingestion.aws.cloudtrail_resource_activity import (
    CloudTrailResourceActivityIngestor,
)
from ingestion.aws.snapshot_events import (
    SnapshotEventIngestor,
    normalize_snapshot_service_event,
)


def ct_delete(event_id="ct-batch-1", **overrides):
    record = {
        "eventVersion": "1.09",
        "eventID": event_id,
        "eventTime": "2026-09-10T12:00:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "DeleteObject",
        "awsRegion": "us-east-1",
        "recipientAccountId": "111122223333",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/x",
                         "userName": "x"},
        "requestParameters": {"bucketName": "b", "key": "k"},
    }
    record.update(overrides)
    return record


class TestCloudTrailIngestor:
    def test_batch_normalization(self):
        ingestor = CloudTrailResourceActivityIngestor()
        result = ingestor.ingest_batch([ct_delete(f"e{i}") for i in range(3)])
        assert result.ok
        assert len(result.events) == 3
        assert result.total == 3

    def test_records_payload_shape_accepted(self):
        ingestor = CloudTrailResourceActivityIngestor()
        result = ingestor.ingest_batch({"Records": [ct_delete("wrapped-1")]})
        assert len(result.events) == 1

    def test_unsupported_records_skipped_not_malformed(self):
        ingestor = CloudTrailResourceActivityIngestor()
        result = ingestor.ingest_batch(
            [ct_delete("ok-1"),
             ct_delete("console-1", eventName="ConsoleLogin", eventSource="signin.amazonaws.com")]
        )
        assert len(result.events) == 1
        assert len(result.skipped) == 1
        assert result.ok

    def test_strict_mode_raises_on_malformed(self):
        ingestor = CloudTrailResourceActivityIngestor(strict=True)
        with pytest.raises(MalformedEventError):
            ingestor.ingest_batch([{"eventVersion": "1.09"}])

    def test_lenient_mode_quarantines_malformed(self):
        ingestor = CloudTrailResourceActivityIngestor(strict=False)
        result = ingestor.ingest_batch([ct_delete("good"), {"eventVersion": "1.09"}])
        assert len(result.events) == 1
        assert len(result.quarantined) == 1
        assert not result.ok
        assert result.quarantined[0]["record"] == {"eventVersion": "1.09"}

    def test_oversized_batch_rejected(self):
        ingestor = CloudTrailResourceActivityIngestor(max_records_per_batch=2)
        with pytest.raises(MalformedEventError):
            ingestor.ingest_batch([ct_delete(f"e{i}") for i in range(3)])

    def test_replay_flags_propagated(self):
        ingestor = CloudTrailResourceActivityIngestor()
        result = ingestor.ingest_batch(
            [ct_delete("replay-1")], is_replayed=True, is_synthetic=True, generator="fixture"
        )
        event = result.events[0]
        assert event.data_provenance.is_replayed
        assert event.data_provenance.is_synthetic
        assert event.data_provenance.generator == "fixture"


def eb_backup(event_id, state, detail_type="Backup Job State Change", vault="fin-prod-vault"):
    return {
        "version": "0",
        "id": event_id,
        "detail-type": detail_type,
        "source": "aws.backup",
        "account": "111122223333",
        "time": "2026-09-10T13:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "jobId": "job-1",
            "state": state,
            "backupVaultArn": f"arn:aws:backup:us-east-1:111122223333:backup-vault:{vault}",
            "recoveryPointArn": (
                f"arn:aws:backup:us-east-1:111122223333:backup-vault:{vault}/recovery-point/rp-1"
            ),
        },
    }


class TestBackupEvents:
    def test_destructive_state_maps_to_recovery_point_delete(self):
        event = normalize_backup_service_event(eb_backup("b1", "EXPIRED"))
        assert event.action_category is ActionCategory.RECOVERY_POINT_DELETE
        assert event.operation_type is OperationType.RECOVERY_IMPAIRING
        assert event.recovery_point_id == "rp-1"
        assert event.backup_vault_name == "fin-prod-vault"
        assert event.raw_action == "backup:Backup Job State Change:EXPIRED"

    def test_completed_backup_job_is_create(self):
        event = normalize_backup_service_event(eb_backup("b2", "COMPLETED"))
        assert event.action_category is ActionCategory.CREATE
        assert not event.is_destructive

    def test_restore_job(self):
        event = normalize_backup_service_event(
            eb_backup("b3", "COMPLETED", detail_type="Restore Job State Change")
        )
        assert event.action_category is ActionCategory.RESTORE

    def test_missing_detail_rejected(self):
        record = eb_backup("b4", "COMPLETED")
        del record["detail"]
        with pytest.raises(MalformedEventError):
            normalize_backup_service_event(record)

    def test_missing_id_rejected(self):
        record = eb_backup("", "COMPLETED")
        with pytest.raises(MalformedEventError):
            normalize_backup_service_event(record)

    def test_out_of_scope_detail_type_skipped(self):
        with pytest.raises(UnsupportedEventError):
            normalize_backup_service_event(
                eb_backup("b5", "COMPLETED", detail_type="Some Other Detail Type")
            )

    def test_batch_ingestor_dispositions(self):
        ingestor = BackupEventIngestor()
        outcome = ingestor.ingest_batch(
            [eb_backup("ok-1", "EXPIRED"), eb_backup("bad", "COMPLETED", detail_type="Unknown")]
        )
        assert len(outcome["events"]) == 1
        assert len(outcome["skipped"]) == 1


def eb_snapshot(event_id, detail_type, detail):
    return {
        "version": "0",
        "id": event_id,
        "detail-type": detail_type,
        "source": "aws.ec2",
        "account": "111122223333",
        "time": "2026-09-10T14:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": detail,
    }


class TestSnapshotEvents:
    def test_ec2_snapshot_delete(self):
        event = normalize_snapshot_service_event(
            eb_snapshot("s1", "EC2 Snapshot Delete", {"source": "snap-0abc", "state": "deleted"})
        )
        assert event.action_category is ActionCategory.SNAPSHOT_DELETE
        assert event.snapshot_id == "snap-0abc"
        assert event.resource_type is ResourceType.EBS_SNAPSHOT

    def test_ec2_snapshot_create(self):
        event = normalize_snapshot_service_event(
            eb_snapshot("s2", "EC2 Snapshot Create", {"source": "snap-0def", "state": "completed"})
        )
        assert event.action_category is ActionCategory.CREATE

    def test_rds_snapshot_deletion_by_event_id(self):
        event = normalize_snapshot_service_event(
            eb_snapshot(
                "s3",
                "RDS DB Snapshot Event",
                {"SourceIdentifier": "snap-0rds", "EventID": "RDS-EVENT-0058",
                 "Message": "Manual snapshot deleted"},
            )
        )
        assert event.action_category is ActionCategory.SNAPSHOT_DELETE
        assert event.resource_type is ResourceType.RDS_SNAPSHOT
        assert event.raw_action == "rds:RDS DB Snapshot Event:RDS-EVENT-0058"

    def test_out_of_scope_skipped(self):
        with pytest.raises(UnsupportedEventError):
            normalize_snapshot_service_event(
                eb_snapshot("s4", "EC2 Instance State-change Notification",
                            {"instance-id": "i-1", "state": "terminated"})
            )

    def test_batch_ingestor(self):
        ingestor = SnapshotEventIngestor()
        outcome = ingestor.ingest_batch(
            [
                eb_snapshot("ok", "EC2 Snapshot Delete", {"source": "snap-0abc"}),
                eb_snapshot("bad", "EC2 AMI State Change", {"state": "available"}),
            ]
        )
        assert len(outcome["events"]) == 1
        assert len(outcome["skipped"]) == 1
