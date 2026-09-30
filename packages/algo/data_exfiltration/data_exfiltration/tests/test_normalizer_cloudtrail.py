"""CloudTrail normalizer unit tests: happy paths, gaps, missing fields, malformed."""

from __future__ import annotations

import pytest

from algo.data_exfiltration.data_exfiltration.exceptions import (
    MalformedEventError,
    SchemaVersionError,
    UnsupportedEventError,
)
from algo.data_exfiltration.data_exfiltration.measurement import MeasurementConfidence, MeasurementSource
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.schemas import (
    ActorType,
    DataAction,
    Provider,
    ReadOrWrite,
    ValuePresence,
)

from .fixtures.cloudtrail_records import (
    DDB_QUERY,
    S3_COPY,
    S3_ERROR,
    S3_GET,
    S3_GET_ROLE,
    S3_LIST,
    S3_PUT,
    S3_UNAUTH,
)
from .fixtures.gaps import GAPS


@pytest.fixture()
def nx() -> EventNormalizer:
    return EventNormalizer()


class TestHappyPath:
    def test_get_object(self, nx) -> None:
        event = nx.normalize_cloudtrail(S3_GET)
        assert event.provider is Provider.AWS
        assert event.event_id == S3_GET["eventID"]
        assert event.actor_id == S3_GET["arn"]
        assert event.actor_type is ActorType.IAM_USER
        assert event.data_action is DataAction.READ_OBJECT
        assert event.read_or_write is ReadOrWrite.READ
        assert event.bucket == "prod-customer-data"
        assert event.object_key == "exports/customers-2024.csv"
        assert event.resource_id == "s3://prod-customer-data"
        assert event.account_id == "111122223333"
        assert event.region == "us-east-1"
        assert event.event_time_epoch_ms is not None

    def test_bytes_estimated_with_provenance(self, nx) -> None:
        event = nx.normalize_cloudtrail(S3_GET)
        assert event.bytes_accessed is not None
        assert event.bytes_accessed.value == 10485760
        contribution = event.bytes_accessed.measurements[0]
        assert contribution.source is MeasurementSource.CLOUDTRAIL
        assert contribution.confidence is MeasurementConfidence.ESTIMATED
        assert event.bytes_accessed_presence is ValuePresence.ESTIMATED
        assert event.bytes_accessed_availability is MeasurementConfidence.ESTIMATED

    def test_put_object_is_write(self, nx) -> None:
        event = nx.normalize_cloudtrail(S3_PUT)
        assert event.data_action is DataAction.WRITE_OBJECT
        assert event.read_or_write is ReadOrWrite.WRITE

    def test_list_maps_to_enumerate(self, nx) -> None:
        event = nx.normalize_cloudtrail(S3_LIST)
        assert event.data_action is DataAction.ENUMERATE
        assert event.read_or_write is ReadOrWrite.READ

    def test_copy_maps_to_copy(self, nx) -> None:
        event = nx.normalize_cloudtrail(S3_COPY)
        assert event.data_action is DataAction.COPY
        assert event.read_or_write is ReadOrWrite.BOTH

    def test_assumed_role_actor(self, nx) -> None:
        event = nx.normalize_cloudtrail(S3_GET_ROLE)
        assert event.actor_type is ActorType.ASSUMED_ROLE
        assert "assumed-role/BackupOperator" in event.actor_id

    def test_error_code_preserved(self, nx) -> None:
        event = nx.normalize_cloudtrail(S3_ERROR)
        assert event.error_code == "AccessDenied"
        assert event.data_action is DataAction.READ_OBJECT

    def test_unidentified_actor_is_none(self, nx) -> None:
        event = nx.normalize_cloudtrail(S3_UNAUTH)
        assert event.actor_id is None
        assert event.actor_type is ActorType.UNKNOWN

    def test_dynamodb_get_item(self, nx) -> None:
        event = nx.normalize_cloudtrail(DDB_QUERY)
        assert event.resource_type == "dynamodb_table"
        assert event.table == "CustomerProfiles"
        assert event.resource_arn == (
            "arn:aws:dynamodb:us-east-1:111122223333:table/CustomerProfiles"
        )
        assert event.data_action is DataAction.READ_OBJECT


class TestUnsupportedAndMalformed:
    def test_management_event_is_unsupported(self, nx) -> None:
        record = {**S3_GET, "eventName": "ListBuckets", "eventCategory": "Management"}
        with pytest.raises(UnsupportedEventError):
            nx.normalize_cloudtrail(record)

    def test_unknown_event_name_is_unsupported(self, nx) -> None:
        record = {**S3_GET, "eventName": "SomeFutureApi"}
        with pytest.raises(UnsupportedEventError):
            nx.normalize_cloudtrail(record)

    def test_missing_event_time_is_malformed(self, nx) -> None:
        record = {k: v for k, v in S3_GET.items() if k != "eventTime"}
        with pytest.raises(MalformedEventError):
            nx.normalize_cloudtrail(record)

    def test_missing_event_name_is_malformed(self, nx) -> None:
        record = {k: v for k, v in S3_GET.items() if k != "eventName"}
        with pytest.raises(MalformedEventError):
            nx.normalize_cloudtrail(record)

    def test_unsupported_schema_version(self, nx) -> None:
        record = {**S3_GET, "eventVersion": "9.99"}
        with pytest.raises(SchemaVersionError):
            nx.normalize_cloudtrail(record)

    def test_non_dict_input_is_malformed(self, nx) -> None:
        with pytest.raises(MalformedEventError):
            nx.normalize_cloudtrail(["not", "a", "dict"])


class TestCapabilityGaps:
    """GAP fixtures normalize successfully; unavailable fields stay None."""

    @pytest.mark.parametrize("name", sorted(GAPS.keys()))
    def test_gap_normalizes_with_unavailable_fields(self, nx, name) -> None:
        record = GAPS[name]
        event = nx.normalize_cloudtrail(record)
        assert event.event_id
        assert event.provider is Provider.AWS

    def test_gap_missing_region(self, nx) -> None:
        event = nx.normalize_cloudtrail(GAPS["GAP-04 missing awsRegion kept unavailable"])
        assert event.region is None

    def test_gap_arn_not_reconstructed(self, nx) -> None:
        event = nx.normalize_cloudtrail(GAPS["GAP-02 arn not reconstructed for all services"])
        assert event.resource_arn is None
        assert event.resource_id == "s3://prod-customer-data"
