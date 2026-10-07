"""Part 5 tests: GCP Cloud Audit Log ingestion."""

from __future__ import annotations

import pytest

from algo.detection.cloud_destruction.exceptions import (
    MalformedEventError,
    UnsupportedEventError,
)
from algo.detection.cloud_destruction.provenance import UnavailableReason
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    ActorType,
    CloudProvider,
    OperationType,
)
from ingestion.gcp import (
    GCP_NORMALIZER_VERSION,
    GcpAuditLogIngestor,
    GcpAuditLogNormalizer,
)


def availability_of(event) -> dict:
    return {fa.field: fa for fa in event.feature_availability}


def make_entry(
    *,
    method: str = "storage.objects.delete",
    resource_name: str = "projects/_/buckets/fin-prod/objects/reports/x.json",
    insert_id: str = "insert-1",
    principal: str = "alice@example.com",
    timestamp: str = "2026-09-10T12:00:00Z",
    project_id: str = "fin-prod-123",
    **overrides,
) -> dict:
    entry = {
        "logName": "projects/fin-prod-123/logs/cloudaudit.googleapis.com%2Fdata_access",
        "insertId": insert_id,
        "resource": {
            "type": "gcs_object",
            "labels": {"project_id": project_id, "location": "US"},
        },
        "timestamp": timestamp,
        "severity": "NOTICE",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "storage.googleapis.com",
            "methodName": method,
            "resourceName": resource_name,
            "status": {},
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {
                "callerIp": "203.0.113.7",
                "callerSuppliedUserAgent": "gcloud/472.0",
            },
            "request": {"bucket": "fin-prod"},
        },
    }
    entry.update(overrides)
    return entry


class TestGcpNormalizer:
    def test_delete_object_normalizes(self):
        event = GcpAuditLogNormalizer().normalize(make_entry())
        assert event.provider is CloudProvider.GCP
        assert event.action_category is ActionCategory.DELETE
        assert event.operation_type is OperationType.SINGLE
        assert event.raw_action == "storage.objects.delete"
        assert event.resource_arn == make_entry()["protoPayload"]["resourceName"]
        assert event.object_key == "reports/x.json"
        assert event.resource_id == "fin-prod"
        assert event.account_id == "fin-prod-123"
        assert event.region == "US"
        assert event.source_ip == "203.0.113.7"
        assert event.user_agent == "gcloud/472.0"
        assert event.event_id == "insert-1"

    def test_normalizer_version_is_stamped(self):
        event = GcpAuditLogNormalizer().normalize(make_entry())
        assert event.data_provenance.normalizer_version == GCP_NORMALIZER_VERSION
        assert event.data_provenance.source_type == "gcp_audit_log"
        assert event.data_provenance.ingestion_pipeline == "gcp.audit_log"

    @pytest.mark.parametrize(
        ("method", "category"),
        [
            ("storage.objects.delete", ActionCategory.DELETE),
            ("storage.buckets.delete", ActionCategory.DELETE),
            ("storage.objects.copy", ActionCategory.REWRITE),
            ("storage.objects.update", ActionCategory.MODIFY),
            ("storage.buckets.setIamPolicy", ActionCategory.POLICY_CHANGE),
            ("storage.buckets.lockRetentionPolicy", ActionCategory.PROTECTION_CHANGE),
            ("compute.instances.delete", ActionCategory.DELETE),
            ("compute.disks.delete", ActionCategory.DELETE),
            ("compute.snapshots.delete", ActionCategory.SNAPSHOT_DELETE),
            ("sql.instances.delete", ActionCategory.DELETE),
            ("bigquery.tables.delete", ActionCategory.DELETE),
            ("spanner.databases.delete", ActionCategory.DELETE),
            ("iam.roles.delete", ActionCategory.POLICY_CHANGE),
            ("iam.serviceAccounts.delete", ActionCategory.DELETE),
        ],
    )
    def test_curated_method_mapping(self, method, category):
        entry = make_entry(method=method, resource_name=f"projects/_/x/{method.split('.')[-2]}/target")
        event = GcpAuditLogNormalizer().normalize(entry)
        assert event.action_category is category

    def test_snapshot_suffix_rule_classifies_snapshot_delete(self):
        event = GcpAuditLogNormalizer().normalize(
            make_entry(method="compute.snapshots.delete", resource_name="projects/p/global/snapshots/snap-1")
        )
        assert event.action_category is ActionCategory.SNAPSHOT_DELETE
        assert event.snapshot_id == "snap-1"
        assert event.resource_id == "snap-1"

    def test_generic_backup_and_recovery_point_rules(self):
        backup = GcpAuditLogNormalizer().normalize(
            make_entry(
                method="backupdr.projects.backupVaults.backups.delete",
                resource_name="projects/p/backupVaults/v/backups/bk",
            )
        )
        assert backup.action_category is ActionCategory.BACKUP_DELETE
        recovery = GcpAuditLogNormalizer().normalize(
            make_entry(
                method="backupdr.projects.backupVaults.recoveryPoints.delete",
                resource_name="projects/p/backupVaults/v/recoveryPoints/rp",
            )
        )
        assert recovery.action_category is ActionCategory.RECOVERY_POINT_DELETE

    def test_undelete_restores(self):
        event = GcpAuditLogNormalizer().normalize(
            make_entry(method="storage.objects.undelete")
        )
        assert event.action_category is ActionCategory.RESTORE

    def test_actor_mapping(self):
        user = GcpAuditLogNormalizer().normalize(
            make_entry(principal="alice@example.com")
        )
        assert user.actor_id == "alice@example.com"
        assert user.actor_type is ActorType.IAM_USER
        service = GcpAuditLogNormalizer().normalize(
            make_entry(principal="destroyer@my-project.iam.gserviceaccount.com")
        )
        assert service.actor_type is ActorType.SERVICE_ACCOUNT

    def test_missing_actor_records_unavailability(self):
        entry = make_entry()
        del entry["protoPayload"]["authenticationInfo"]
        event = GcpAuditLogNormalizer().normalize(entry)
        assert event.actor_id is None
        assert event.actor_type is ActorType.UNKNOWN
        availability = availability_of(event)
        assert availability["actor_id"].reason is UnavailableReason.NOT_IN_SOURCE

    def test_operation_id_becomes_session_id(self):
        entry = make_entry()
        entry["protoPayload"]["operation"] = {
            "id": "op-chain-42",
            "first": True,
            "last": True,
        }
        event = GcpAuditLogNormalizer().normalize(entry)
        assert event.session_id == "op-chain-42"

    def test_failed_call_is_evidence_with_note(self):
        entry = make_entry()
        entry["protoPayload"]["status"] = {"code": 7, "message": "PERMISSION_DENIED"}
        event = GcpAuditLogNormalizer().normalize(entry)
        assert event.action_category is ActionCategory.DELETE
        assert any("status.code=7" in n for n in event.data_provenance.transformation_notes)

    def test_resource_labels_fallback_for_resource_id(self):
        entry = make_entry(resource_name=None)
        entry["resource"]["labels"]["bucket_name"] = "fin-prod"
        event = GcpAuditLogNormalizer().normalize(entry)
        assert event.resource_id == "fin-prod"

    def test_project_from_log_name_fallback(self):
        entry = make_entry()
        entry["resource"]["labels"].pop("project_id")
        event = GcpAuditLogNormalizer().normalize(entry)
        assert event.account_id == "fin-prod-123"

    def test_region_from_resource_location_fallback(self):
        entry = make_entry()
        entry["resource"]["labels"].pop("location")
        entry["protoPayload"]["resourceLocation"] = {"currentLocations": ["europe-west1"]}
        event = GcpAuditLogNormalizer().normalize(entry)
        assert event.region == "europe-west1"

    def test_event_id_falls_back_to_content_hash(self):
        entry = make_entry()
        entry.pop("insertId")
        event = GcpAuditLogNormalizer().normalize(entry)
        assert event.event_id.startswith("gcp-audit:")
        # Deterministic: same entry content -> same id.
        event2 = GcpAuditLogNormalizer().normalize(
            {k: v for k, v in make_entry().items() if k != "insertId"}
        )
        assert event.event_id == event2.event_id

    def test_request_parameters_kept(self):
        event = GcpAuditLogNormalizer().normalize(make_entry())
        assert event.request_parameters == {"bucket": "fin-prod"}

    def test_replay_flags_propagate(self):
        event = GcpAuditLogNormalizer().normalize(
            make_entry(), is_replayed=True, is_synthetic=True, generator="test"
        )
        assert event.data_provenance.is_replayed
        assert event.data_provenance.is_synthetic
        assert event.data_provenance.generator == "test"

    def test_protection_fields_unavailable_without_catalog(self):
        event = GcpAuditLogNormalizer().normalize(make_entry())
        availability = availability_of(event)
        for field_name in (
            "versioning_enabled",
            "object_lock_enabled",
            "backup_enabled",
            "business_criticality",
        ):
            assert availability[field_name].reason is UnavailableReason.ENRICHMENT_MISSING

    def test_catalog_enrichment(self):
        from algo.detection.cloud_destruction.protection import StaticProtectionCatalog
        from algo.detection.cloud_destruction.schemas import (
            BusinessCriticality,
            ResourceProtectionProfile,
            ResourceType,
        )

        catalog = StaticProtectionCatalog()
        catalog.add(
            ResourceProtectionProfile(
                resource_id="projects/_/buckets/fin-prod/objects/reports/x.json",
                resource_type=ResourceType.UNKNOWN,
                versioning_enabled=True,
                object_lock_enabled=True,
                backup_enabled=True,
                snapshot_protection_enabled=True,
                business_criticality=BusinessCriticality.CRITICAL,
                retention_configuration={"retention_days": 30},
            )
        )
        event = GcpAuditLogNormalizer(catalog=catalog).normalize(make_entry())
        assert event.versioning_enabled is True
        assert event.object_lock_enabled is True
        assert event.backup_enabled is True
        assert event.snapshot_protection_enabled is True
        assert event.retention_period == 30
        assert event.business_criticality.value == "critical"
        availability = availability_of(event)
        assert availability["versioning_enabled"].presence.value == "enriched"

    def test_catalog_miss_stays_unavailable(self):
        from algo.detection.cloud_destruction.protection import StaticProtectionCatalog

        event = GcpAuditLogNormalizer(
            catalog=StaticProtectionCatalog()
        ).normalize(make_entry())
        availability = availability_of(event)
        assert (
            availability["versioning_enabled"].reason
            is UnavailableReason.ENRICHMENT_MISSING
        )

    def test_non_audit_log_is_skipped(self):
        entry = make_entry()
        entry["logName"] = "projects/p/logs/storage.googleapis.com%2Fstorage_write"
        with pytest.raises(UnsupportedEventError):
            GcpAuditLogNormalizer().normalize(entry)

    def test_non_audit_payload_type_is_skipped(self):
        entry = make_entry()
        entry["protoPayload"]["@type"] = "type.googleapis.com/google.cloud.Other"
        with pytest.raises(UnsupportedEventError):
            GcpAuditLogNormalizer().normalize(entry)

    @pytest.mark.parametrize(
        "method",
        [
            "storage.objects.list",
            "storage.objects.create",
            "compute.instances.insert",
            "bigquery.jobs.query",
            "storage.objects.get",
        ],
    )
    def test_read_and_create_operations_are_out_of_scope(self, method):
        with pytest.raises(UnsupportedEventError):
            GcpAuditLogNormalizer().normalize(make_entry(method=method))

    def test_malformed_records_raise(self):
        with pytest.raises(MalformedEventError):
            GcpAuditLogNormalizer().normalize(
                {"logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity"}
            )  # no protoPayload
        with pytest.raises(MalformedEventError):
            GcpAuditLogNormalizer().normalize(
                make_entry() | {"timestamp": "not-a-timestamp"}
            )
        entry = make_entry()
        del entry["protoPayload"]["methodName"]
        with pytest.raises(MalformedEventError):
            GcpAuditLogNormalizer().normalize(entry)
        with pytest.raises(MalformedEventError):
            GcpAuditLogNormalizer().normalize("not-a-dict")

    def test_bad_timestamp_format_raises(self):
        with pytest.raises(MalformedEventError):
            GcpAuditLogNormalizer().normalize(make_entry(timestamp="2026/09/10 12:00"))


class TestGcpIngestor:
    def test_batch_dispositions(self):
        payload = [
            make_entry(insert_id="e1"),
            make_entry(insert_id="e2", method="storage.objects.list"),
            make_entry(insert_id="e3") | {"timestamp": "bad"},
        ]
        result = GcpAuditLogIngestor(strict=False).ingest_batch(payload)
        assert len(result.events) == 1
        assert len(result.skipped) == 1
        assert len(result.quarantined) == 1
        assert result.total == 3
        assert result.ok is False

    def test_strict_mode_raises_on_malformed(self):
        payload = [make_entry() | {"timestamp": "bad"}]
        with pytest.raises(MalformedEventError):
            GcpAuditLogIngestor(strict=True).ingest_batch(payload)

    def test_payload_unwrapping(self):
        for key in ("entries", "auditLogs", "audit_logs"):
            result = GcpAuditLogIngestor(strict=False).ingest_batch(
                {key: [make_entry(insert_id="x1")]}
            )
            assert len(result.events) == 1

    def test_invalid_payload_raises(self):
        with pytest.raises(MalformedEventError):
            GcpAuditLogIngestor().ingest_batch({"nope": 1})
        with pytest.raises(MalformedEventError):
            GcpAuditLogIngestor().ingest_batch(42)

    def test_max_records_per_batch(self):
        payload = [make_entry(insert_id=f"e{i}") for i in range(10)]
        with pytest.raises(MalformedEventError):
            GcpAuditLogIngestor(max_records_per_batch=5).ingest_batch(payload)

    def test_raw_reference_is_stable_pointer(self):
        from ingestion.gcp.audit_log import raw_reference_for

        entry = make_entry()
        assert raw_reference_for(entry, 3) == "gcp-audit://insert-1"
        assert raw_reference_for({}, 7) == "gcp-audit://7"

    def test_provenance_flags_flow_through_ingestor(self):
        result = GcpAuditLogIngestor().ingest_batch(
            [make_entry(insert_id="e1")],
            is_replayed=True,
            is_synthetic=True,
            generator="replay-engine",
        )
        assert result.events[0].data_provenance.is_replayed
        assert result.events[0].data_provenance.generator == "replay-engine"
