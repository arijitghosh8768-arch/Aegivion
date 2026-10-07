"""Normalizer unit tests: CloudTrail mapping, availability, provenance."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from detection.cloud_destruction.normalizer import (
    ResourceActivityNormalizer,
    classify_action,
)
from detection.cloud_destruction.protection import (
    ProtectionState,
    StaticProtectionCatalog,
)
from detection.cloud_destruction.provenance import UnavailableReason, ValuePresence
from detection.cloud_destruction.schemas import (
    ActionCategory,
    BusinessCriticality,
    OperationType,
    ResourceType,
)


def s3_delete_record(**overrides):
    record = {
        "eventVersion": "1.09",
        "eventID": "ct-001",
        "eventTime": "2026-09-10T12:00:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "DeleteObject",
        "awsRegion": "us-east-1",
        "recipientAccountId": "111122223333",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "aws-cli/2.15.0",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::111122223333:user/attacker",
            "userName": "attacker",
        },
        "requestParameters": {"bucketName": "fin-prod-archive", "key": "ledger/001.pq"},
        "resources": [{"ARN": "arn:aws:s3:::fin-prod-archive/ledger/001.pq"}],
    }
    record.update(overrides)
    return record


class TestClassifyAction:
    def test_s3_delete(self):
        mapping = classify_action("s3", "DeleteObject")
        assert mapping is not None
        assert mapping[0] is ActionCategory.DELETE

    def test_backup_recovery_point_delete(self):
        mapping = classify_action("backup", "DeleteRecoveryPoint")
        assert mapping is not None
        assert mapping[0] is ActionCategory.RECOVERY_POINT_DELETE

    def test_full_event_source_accepted(self):
        mapping = classify_action("s3.amazonaws.com", "DeleteObject")
        assert mapping is not None

    def test_unsupported_returns_none(self):
        assert classify_action("s3", "ListObjectsV2") is None
        assert classify_action("signin", "ConsoleLogin") is None
        assert classify_action("", "") is None


class TestCloudTrailNormalization:
    def setup_method(self):
        self.normalizer = ResourceActivityNormalizer()

    def test_basic_s3_delete(self):
        event = self.normalizer.normalize_cloudtrail(s3_delete_record())
        assert event.event_id == "ct-001"
        assert event.timestamp == datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
        assert event.actor_id == "arn:aws:iam::111122223333:user/attacker"
        assert event.actor_type.value == "iam_user"
        assert event.resource_id == "fin-prod-archive"
        assert event.resource_arn == "arn:aws:s3:::fin-prod-archive/ledger/001.pq"
        assert event.object_key == "ledger/001.pq"
        assert event.action_category is ActionCategory.DELETE
        assert event.raw_action == "s3:DeleteObject"
        assert event.account_id == "111122223333"
        assert event.region == "us-east-1"
        assert event.source_ip == "203.0.113.10"
        assert event.is_destructive

    def test_raw_action_preserved_as_evidence(self):
        event = self.normalizer.normalize_cloudtrail(
            s3_delete_record(eventName="DeleteObjects")
        )
        assert event.action_category is ActionCategory.DELETE
        assert event.operation_type is OperationType.BATCH
        assert event.raw_action == "s3:DeleteObjects"

    def test_version_deletion_mapping(self):
        event = self.normalizer.normalize_cloudtrail(
            s3_delete_record(
                eventName="DeleteObjectVersion",
                requestParameters={
                    "bucketName": "fin-prod-archive",
                    "key": "ledger/001.pq",
                    "versionId": "vId-123",
                },
            )
        )
        assert event.action_category is ActionCategory.VERSION_DELETE
        assert event.version_id == "vId-123"

    def test_delete_marker_detected(self):
        event = self.normalizer.normalize_cloudtrail(
            s3_delete_record(
                responseElements={
                    "x-amz-delete-marker": "true",
                    "x-amz-version-id": "marker.abc",
                }
            )
        )
        assert event.is_delete_marker
        assert event.operation_type is OperationType.DELETE_MARKER

    def test_snapshot_delete(self):
        event = self.normalizer.normalize_cloudtrail(
            {
                "eventVersion": "1.09",
                "eventID": "ct-002",
                "eventTime": "2026-09-10T12:05:00Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "DeleteSnapshot",
                "awsRegion": "us-east-1",
                "recipientAccountId": "111122223333",
                "userIdentity": {"type": "AssumedRole",
                                 "arn": "arn:aws:sts::111122223333:assumed-role/x/y",
                                 "sessionContext": {"sessionIssuer": {"userName": "x"}}},
                "requestParameters": {"SnapshotId": "snap-0abc123"},
                "resources": [{"ARN": "arn:aws:ec2:us-east-1:111122223333:snapshot/snap-0abc123"}],
            }
        )
        assert event.action_category is ActionCategory.SNAPSHOT_DELETE
        assert event.snapshot_id == "snap-0abc123"
        assert event.resource_type is ResourceType.EBS_SNAPSHOT
        assert event.actor_type.value == "assumed_role"
        assert event.session_id == "x"

    def test_recovery_point_delete(self):
        arn = (
            "arn:aws:backup:us-east-1:111122223333:"
            "backup-vault:fin-prod-vault/recovery-point/rp-42"
        )
        event = self.normalizer.normalize_cloudtrail(
            {
                "eventVersion": "1.09",
                "eventID": "ct-003",
                "eventTime": "2026-09-10T12:10:00Z",
                "eventSource": "backup.amazonaws.com",
                "eventName": "DeleteRecoveryPoint",
                "awsRegion": "us-east-1",
                "recipientAccountId": "111122223333",
                "userIdentity": {"type": "IAMUser",
                                 "arn": "arn:aws:iam::111122223333:user/attacker",
                                 "userName": "attacker"},
                "requestParameters": {
                    "BackupVaultName": "fin-prod-vault",
                    "RecoveryPointArn": arn,
                },
                "resources": [{"ARN": arn}],
            }
        )
        assert event.action_category is ActionCategory.RECOVERY_POINT_DELETE
        assert event.recovery_point_id == "rp-42"
        assert event.backup_vault_name == "fin-prod-vault"
        assert event.resource_type is ResourceType.RECOVERY_POINT

    def test_protection_change(self):
        event = self.normalizer.normalize_cloudtrail(
            s3_delete_record(
                eventName="PutBucketVersioning",
                requestParameters={
                    "bucketName": "fin-prod-archive",
                    "VersioningConfiguration": {"Status": "Suspended"},
                },
                resources=[{"ARN": "arn:aws:s3:::fin-prod-archive"}],
            )
        )
        assert event.action_category is ActionCategory.PROTECTION_CHANGE
        assert event.resource_type is ResourceType.S3_BUCKET
        assert event.is_recovery_impairing

    def test_unsupported_event_raises_unsupported_not_malformed(self):
        with pytest.raises(UnsupportedEventError):
            self.normalizer.normalize_cloudtrail(
                s3_delete_record(eventName="ConsoleLogin", eventSource="signin.amazonaws.com")
            )

    def test_missing_event_id_raises_malformed(self):
        with pytest.raises(MalformedEventError):
            self.normalizer.normalize_cloudtrail(s3_delete_record(eventID=""))

    def test_missing_event_name_raises_malformed(self):
        record = s3_delete_record()
        del record["eventName"]
        with pytest.raises(MalformedEventError):
            self.normalizer.normalize_cloudtrail(record)

    def test_bad_timestamp_raises_malformed(self):
        with pytest.raises(MalformedEventError):
            self.normalizer.normalize_cloudtrail(s3_delete_record(eventTime="yesterday-ish"))

    def test_non_dict_raises_malformed(self):
        with pytest.raises(MalformedEventError):
            self.normalizer.normalize_cloudtrail(["not", "a", "dict"])

    def test_root_actor_fallback(self):
        event = self.normalizer.normalize_cloudtrail(
            s3_delete_record(
                userIdentity={"type": "Root", "accountId": "111122223333"},
                sourceIPAddress="",
            )
        )
        assert event.actor_id == "root:111122223333"
        assert event.actor_type.value == "root"
        assert event.source_ip is None

    def test_availability_records_missing_actor(self):
        event = self.normalizer.normalize_cloudtrail(
            s3_delete_record(userIdentity=None)
        )
        availability = event.availability_map()
        assert not availability["actor_id"].is_available
        assert availability["actor_id"].reason is UnavailableReason.NOT_IN_SOURCE
        assert availability["event_id"].is_available

    def test_availability_records_enrichment_missing_without_catalog(self):
        event = self.normalizer.normalize_cloudtrail(s3_delete_record())
        availability = event.availability_map()
        for field in ("business_criticality", "backup_enabled", "versioning_enabled"):
            assert not availability[field].is_available
            assert availability[field].reason is UnavailableReason.ENRICHMENT_MISSING

    def test_object_count_derived_for_batch(self):
        event = self.normalizer.normalize_cloudtrail(
            s3_delete_record(
                eventName="DeleteObjects",
                requestParameters={
                    "bucketName": "fin-prod-archive",
                    "Delete": {"Objects": [{"Key": f"k{i}"} for i in range(7)]},
                },
            )
        )
        assert event.object_count == 7
        availability = event.availability_map()
        assert availability["object_count"].presence is ValuePresence.DERIVED

    def test_single_delete_object_count_defaults_to_one(self):
        event = self.normalizer.normalize_cloudtrail(s3_delete_record())
        assert event.object_count == 1

    def test_provenance_metadata(self):
        event = self.normalizer.normalize_cloudtrail(
            s3_delete_record(), raw_event_reference="cloudtrail://ct-001", raw_record_index=3
        )
        assert event.data_provenance is not None
        assert event.data_provenance.source_type == "cloudtrail"
        assert event.data_provenance.raw_reference == "cloudtrail://ct-001"
        assert event.data_provenance.raw_record_index == 3
        assert not event.data_provenance.is_synthetic

    def test_bytes_changed_never_invented(self):
        event = self.normalizer.normalize_cloudtrail(s3_delete_record())
        assert event.bytes_changed is None
        assert not event.availability_map()["bytes_changed"].is_available


class TestCatalogEnrichment:
    def test_catalog_enriches_protection_fields(self):
        catalog = StaticProtectionCatalog()
        # build through profiles to reuse mapping logic
        from detection.cloud_destruction.schemas import ResourceProtectionProfile

        catalog.add(
            ResourceProtectionProfile(
                resource_id="fin-prod-archive",
                resource_arn="arn:aws:s3:::fin-prod-archive",
                business_criticality=BusinessCriticality.CRITICAL,
                versioning_enabled=True,
                object_lock_enabled=True,
                backup_enabled=False,
                retention_configuration={"retention_days": 90},
            )
        )
        normalizer = ResourceActivityNormalizer(catalog=catalog)
        event = normalizer.normalize_cloudtrail(s3_delete_record())
        assert event.business_criticality is BusinessCriticality.CRITICAL
        assert event.versioning_enabled is True
        assert event.object_lock_enabled is True
        assert event.backup_enabled is False
        assert event.retention_period == 90
        availability = event.availability_map()
        assert availability["business_criticality"].presence is ValuePresence.ENRICHED

    def test_arn_lookup_matches_when_id_lookup_misses(self):
        from detection.cloud_destruction.schemas import ResourceProtectionProfile

        catalog = StaticProtectionCatalog()
        catalog.add(
            ResourceProtectionProfile(
                resource_id="vol-0abc",
                resource_arn="arn:aws:ec2:us-east-1:111122223333:volume/vol-0abc",
                business_criticality=BusinessCriticality.HIGH,
            )
        )
        normalizer = ResourceActivityNormalizer(catalog=catalog)
        event = normalizer.normalize_cloudtrail(
            s3_delete_record(
                eventSource="ec2.amazonaws.com",
                eventName="DeleteVolume",
                requestParameters={"VolumeId": "vol-0abc"},
                resources=[{"ARN": "arn:aws:ec2:us-east-1:111122223333:volume/vol-0abc"}],
            )
        )
        assert event.business_criticality is BusinessCriticality.HIGH

    def test_protection_state_unknown_marker(self):
        catalog = StaticProtectionCatalog()
        state = catalog.enrich("missing-resource")
        assert not state.is_known
        assert state.unavailable_reason is UnavailableReason.ENRICHMENT_MISSING


class TestGenericNormalizer:
    def test_canonical_input_accepted(self):
        normalizer = ResourceActivityNormalizer()
        event = normalizer.normalize_generic(
            {
                "event_id": "gen-1",
                "timestamp": "2026-09-10T00:00:00Z",
                "actor_id": "svc@azure",
                "action_category": "delete",
                "resource_id": "container-1",
                "provider": "azure",
            },
            is_synthetic=True,
            generator="unit-test",
        )
        assert event.provider.value == "azure"
        assert event.action_category is ActionCategory.DELETE
        assert event.data_provenance.is_synthetic
        assert event.data_provenance.generator == "unit-test"

    def test_missing_event_id_rejected(self):
        normalizer = ResourceActivityNormalizer()
        with pytest.raises(MalformedEventError):
            normalizer.normalize_generic({"timestamp": "2026-09-10T00:00:00Z"})
