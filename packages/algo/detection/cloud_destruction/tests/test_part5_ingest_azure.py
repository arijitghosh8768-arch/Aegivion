"""Part 5 tests: Azure Activity Log ingestion."""

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
from ingestion.azure import (
    AZURE_NORMALIZER_VERSION,
    AzureActivityLogIngestor,
    AzureActivityLogNormalizer,
)


def availability_of(event) -> dict:
    return {fa.field: fa for fa in event.feature_availability}


def make_record(
    *,
    operation: str = "Microsoft.Storage/storageAccounts/delete",
    resource_id: str = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/finprod",
    record_id: str = "rec-1",
    correlation_id: str = "corr-1",
    caller: str = "alice@contoso.com",
    time: str = "2026-09-10T12:00:00Z",
    category: str = "Administrative",
    subscription: str = "sub-1",
    location: str = "westus",
    result_type: str = "Succeeded",
    **overrides,
) -> dict:
    record = {
        "recordId": record_id,
        "correlationId": correlation_id,
        "category": category,
        "time": time,
        "resourceId": resource_id,
        "operationName": operation,
        "resultType": result_type,
        "caller": caller,
        "subscriptionId": subscription,
        "location": location,
    }
    record.update(overrides)
    return record


class TestAzureNormalizer:
    def test_delete_storage_account(self):
        event = AzureActivityLogNormalizer().normalize(make_record())
        assert event.provider is CloudProvider.AZURE
        assert event.action_category is ActionCategory.DELETE
        assert event.operation_type is OperationType.SINGLE
        assert event.raw_action == (
            "Microsoft.Storage/storageAccounts/delete"
        )
        assert event.resource_id == "finprod"
        assert event.resource_arn == make_record()["resourceId"]
        assert event.account_id == "sub-1"
        assert event.region == "westus"
        assert event.event_id == "corr-1"

    def test_normalizer_version_and_provenance(self):
        event = AzureActivityLogNormalizer().normalize(make_record())
        assert event.data_provenance.normalizer_version == (
            AZURE_NORMALIZER_VERSION
        )
        assert event.data_provenance.source_type == "azure_activity_log"
        assert event.data_provenance.ingestion_pipeline == (
            "azure.activity_log"
        )

    def test_blob_delete_extracts_object_key(self):
        event = AzureActivityLogNormalizer().normalize(
            make_record(
                operation=(
                    "Microsoft.Storage/storageAccounts/blobServices/"
                    "containers/blobs/delete"
                ),
                resource_id=(
                    "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
                    "Microsoft.Storage/storageAccounts/finprod/"
                    "blobServices/default/containers/reports/"
                    "blobs/x.json"
                ),
            )
        )
        assert event.action_category is ActionCategory.DELETE
        assert event.object_key == "reports/x.json"
        assert event.resource_id == "finprod"

    def test_keyvault_purge_is_recovery_impairing(self):
        event = AzureActivityLogNormalizer().normalize(
            make_record(
                operation="Microsoft.KeyVault/vaults/purge",
                resource_id=(
                    "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
                    "Microsoft.KeyVault/vaults/kv-1"
                ),
            )
        )
        assert event.action_category is (
            ActionCategory.RECOVERY_POINT_DELETE
        )
        assert event.operation_type is OperationType.RECOVERY_IMPAIRING

    def test_recovery_point_and_snapshot_paths(self):
        recovery = AzureActivityLogNormalizer().normalize(
            make_record(
                operation=(
                    "Microsoft.RecoveryServices/vaults/backupFabrics/"
                    "protectionFabrics/protectionContainers/"
                    "protectedItems/recoveryPoints/delete"
                ),
                resource_id=(
                    "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
                    "Microsoft.RecoveryServices/vaults/v-1/"
                    "backupFabrics/f/protectionContainers/c/"
                    "protectedItems/i/recoveryPoints/rp-1"
                ),
            )
        )
        assert recovery.action_category is (
            ActionCategory.RECOVERY_POINT_DELETE
        )
        assert recovery.recovery_point_id == "rp-1"
        snapshot = AzureActivityLogNormalizer().normalize(
            make_record(
                operation="Microsoft.Compute/snapshots/delete",
                resource_id=(
                    "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
                    "Microsoft.Compute/snapshots/snap-1"
                ),
            )
        )
        assert snapshot.action_category is ActionCategory.SNAPSHOT_DELETE
        assert snapshot.snapshot_id == "snap-1"

    def test_actor_mapping(self):
        user = AzureActivityLogNormalizer().normalize(make_record())
        assert user.actor_id == "alice@contoso.com"
        assert user.actor_type is ActorType.IAM_USER
        service = AzureActivityLogNormalizer().normalize(
            make_record(caller="8f2d1c9a-1234-4abc-9def-000000000001")
        )
        assert service.actor_type is ActorType.ASSUMED_ROLE

    def test_missing_actor_records_unavailability(self):
        record = make_record()
        record.pop("caller")
        event = AzureActivityLogNormalizer().normalize(record)
        assert event.actor_id is None
        assert event.actor_type is ActorType.UNKNOWN
        availability = availability_of(event)
        assert (
            availability["actor_id"].reason
            is UnavailableReason.NOT_IN_SOURCE
        )

    def test_subscription_falls_back_to_resource_id(self):
        record = make_record()
        record.pop("subscriptionId")
        event = AzureActivityLogNormalizer().normalize(record)
        assert event.account_id == "sub-1"

    def test_failed_operation_is_evidence_with_note(self):
        event = AzureActivityLogNormalizer().normalize(
            make_record(result_type="Conflict")
        )
        assert event.action_category is ActionCategory.DELETE
        assert any(
            "resultType=Conflict" in n
            for n in event.data_provenance.transformation_notes
        )

    def test_operation_name_dict_form(self):
        record = make_record()
        record["operationName"] = {
            "value": "Microsoft.Compute/disks/delete"
        }
        event = AzureActivityLogNormalizer().normalize(record)
        assert event.action_category is ActionCategory.DELETE
        assert event.raw_action == "Microsoft.Compute/disks/delete"

    def test_timestamp_parses_fractional_and_offsets(self):
        event = AzureActivityLogNormalizer().normalize(
            make_record(time="2026-09-10T12:00:00.1234567+02:00")
        )
        assert event.timestamp is not None
        assert event.timestamp.utcoffset().total_seconds() == 0

    def test_generic_suffix_rules(self):
        disk = AzureActivityLogNormalizer().normalize(
            make_record(
                operation="Microsoft.SomeProvider/customThings/delete",
                resource_id=(
                    "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
                    "Microsoft.SomeProvider/customThings/thing-1"
                ),
            )
        )
        assert disk.action_category is ActionCategory.DELETE
        write = AzureActivityLogNormalizer().normalize(
            make_record(
                operation="Microsoft.SomeProvider/customThings/write",
                resource_id=(
                    "/subscriptions/sub-1/resourceGroups/rg-1/providers/"
                    "Microsoft.SomeProvider/customThings/thing-1"
                ),
            )
        )
        assert write.action_category is ActionCategory.MODIFY

    def test_replay_flags_propagate(self):
        event = AzureActivityLogNormalizer().normalize(
            make_record(),
            is_replayed=True,
            is_synthetic=True,
            generator="replay-engine",
        )
        assert event.data_provenance.is_replayed
        assert event.data_provenance.is_synthetic
        assert event.data_provenance.generator == "replay-engine"

    def test_protection_fields_unavailable_without_catalog(self):
        event = AzureActivityLogNormalizer().normalize(make_record())
        availability = availability_of(event)
        for field_name in (
            "versioning_enabled",
            "object_lock_enabled",
            "backup_enabled",
            "business_criticality",
        ):
            assert (
                availability[field_name].reason
                is UnavailableReason.ENRICHMENT_MISSING
            )

    def test_out_of_scope_category_is_skipped(self):
        with pytest.raises(UnsupportedEventError):
            AzureActivityLogNormalizer().normalize(
                make_record(category="ServiceHealth")
            )

    def test_unmapped_operation_is_skipped(self):
        with pytest.raises(UnsupportedEventError):
            AzureActivityLogNormalizer().normalize(
                make_record(
                    operation="Microsoft.Compute/virtualMachines/start"
                )
            )

    def test_malformed_records_raise(self):
        with pytest.raises(MalformedEventError):
            AzureActivityLogNormalizer().normalize(
                {"resourceId": "x", "operationName": "y"}
            )  # missing time
        with pytest.raises(MalformedEventError):
            AzureActivityLogNormalizer().normalize(
                make_record(time="2026/09/10 12:00")
            )
        with pytest.raises(MalformedEventError):
            AzureActivityLogNormalizer().normalize("not-a-dict")


class TestAzureIngestor:
    def test_batch_dispositions(self):
        payload = [
            make_record(record_id="r1", correlation_id="c1"),
            make_record(
                record_id="r2",
                correlation_id="c2",
                operation="Microsoft.Compute/virtualMachines/start",
            ),
            make_record(record_id="r3", correlation_id="c3", time="bad"),
        ]
        result = AzureActivityLogIngestor(strict=False).ingest_batch(payload)
        assert len(result.events) == 1
        assert len(result.skipped) == 1
        assert len(result.quarantined) == 1
        assert result.total == 3
        assert result.ok is False

    def test_strict_mode_raises_on_malformed(self):
        payload = [make_record(time="bad")]
        with pytest.raises(MalformedEventError):
            AzureActivityLogIngestor(strict=True).ingest_batch(payload)

    def test_payload_unwrapping(self):
        for key in ("value", "records", "Records"):
            result = AzureActivityLogIngestor(strict=False).ingest_batch(
                {key: [make_record(record_id="r1", correlation_id="c1")]}
            )
            assert len(result.events) == 1

    def test_invalid_payload_raises(self):
        with pytest.raises(MalformedEventError):
            AzureActivityLogIngestor().ingest_batch({"nope": 1})

    def test_max_records_per_batch(self):
        payload = [
            make_record(record_id=f"r{i}", correlation_id=f"c{i}")
            for i in range(10)
        ]
        with pytest.raises(MalformedEventError):
            AzureActivityLogIngestor(max_records_per_batch=5).ingest_batch(
                payload
            )

    def test_raw_reference_is_stable_pointer(self):
        from ingestion.azure.activity_log import raw_reference_for

        record = make_record()
        assert raw_reference_for(record, 3) == "azure-activity://rec-1"
        assert raw_reference_for({}, 7) == "azure-activity://7"
