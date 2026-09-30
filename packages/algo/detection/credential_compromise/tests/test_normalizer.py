"""CloudTrail normalizer tests."""

from __future__ import annotations

import pytest

from algo.detection.credential_compromise.exceptions import MalformedEventError
from algo.detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    EventCategory,
    IpIntelligence,
)
from algo.ingestion.aws.cloudtrail import CloudTrailNormalizer
from algo.ingestion.aws.enrichment import StaticIpEnricher


@pytest.fixture
def normalizer() -> CloudTrailNormalizer:
    return CloudTrailNormalizer()


def test_console_login_is_classified_as_signin(cloudtrail, normalizer):
    event = normalizer.normalize(cloudtrail("console_login_mfa.json"))

    assert event.event_name == "ConsoleLogin"
    assert event.service_name == "signin"
    assert event.api_family == ApiFamilies.CONSOLE_SIGNIN
    assert event.event_category is EventCategory.SIGNIN
    assert event.read_or_write is AccessType.READ
    assert event.privilege_change is False
    assert event.mfa_authenticated is True
    assert event.session_creation_time is not None
    assert event.raw_event_reference == (
        "cloudtrail:123456789012:11111111-1111-1111-1111-111111111111"
    )


def test_privilege_mutation_is_flagged(cloudtrail, normalizer):
    event = normalizer.normalize(cloudtrail("iam_put_user_policy.json"))

    assert event.api_family == ApiFamilies.IAM_PRIVILEGE_MUTATION
    assert event.privilege_change is True
    assert event.read_or_write is AccessType.WRITE
    assert event.event_category is EventCategory.MANAGEMENT
    assert event.service_name == "iam"


def test_assumed_role_read_is_data_category(cloudtrail, normalizer):
    event = normalizer.normalize(cloudtrail("s3_get_object.json"))

    assert event.baseline_category is BaselineCategory.ASSUMED_ROLE
    assert event.api_family == ApiFamilies.S3_DATA_READ
    assert event.read_or_write is AccessType.READ
    assert event.event_category is EventCategory.DATA
    assert event.mfa_authenticated is False


def test_federated_assumption_keeps_federated_category(cloudtrail, normalizer):
    event = normalizer.normalize(cloudtrail("assume_role_web_identity.json"))

    assert event.baseline_category is BaselineCategory.FEDERATED_IDENTITY
    assert event.api_family == ApiFamilies.STS_SESSION
    assert event.principal_id == "arn:aws:iam::123456789012:role/CorpAdmin"


def test_service_principal_and_pseudo_ip_warning(cloudtrail, normalizer):
    event = normalizer.normalize(cloudtrail("aws_service_event.json"))

    assert event.baseline_category is BaselineCategory.SERVICE_IDENTITY
    # "autoscaling.amazonaws.com" is a service pseudo-source, not an IP.
    assert event.source_ip is None
    assert any(w.startswith("unparseable_source_ip") for w in event.normalization_warnings)


def test_missing_field_raises_with_missing_fields(cloudtrail, normalizer):
    with pytest.raises(MalformedEventError) as excinfo:
        normalizer.normalize(cloudtrail("malformed_missing_eventname.json"))
    assert "eventName" in excinfo.value.missing_fields


def test_enrichment_is_injected_not_invented(cloudtrail):
    enricher = StaticIpEnricher().add(
        "49.36.12.44",
        IpIntelligence(
            country="IN",
            region_hint="Maharashtra",
            asn=24560,
            asn_org="Bharti Airtel",
        ),
    )
    normalizer = CloudTrailNormalizer(enricher=enricher)
    event = normalizer.normalize(cloudtrail("console_login_mfa.json"))

    assert event.country == "IN"
    assert event.region_hint == "Maharashtra"
    assert event.asn == 24560


def test_without_enrichment_location_stays_unknown(cloudtrail, normalizer):
    event = normalizer.normalize(cloudtrail("console_login_mfa.json"))
    assert event.country is None
    assert event.asn is None
    assert event.region_hint is None


def test_extract_records_accepts_s3_delivery(cloudtrail):
    records = CloudTrailNormalizer.extract_records(cloudtrail("s3_delivery_batch.json"))
    assert len(records) == 2


def test_extract_records_accepts_eventbridge_envelope(cloudtrail):
    record = cloudtrail("console_login_mfa.json")
    records = CloudTrailNormalizer.extract_records({"detail-type": "AWS API Call", "detail": record})
    assert len(records) == 1
    assert records[0]["eventName"] == "ConsoleLogin"


def test_extract_records_rejects_unknown_shape():
    with pytest.raises(MalformedEventError):
        CloudTrailNormalizer.extract_records({"hello": "world"})


def test_batch_quarantines_bad_records_instead_of_dropping(cloudtrail, normalizer):
    payload = {
        "Records": [
            cloudtrail("console_login_mfa.json"),
            cloudtrail("malformed_missing_eventname.json"),
        ]
    }
    result = normalizer.normalize_batch(payload, strict=False)

    assert result.ok_count == 1
    assert result.error_count == 1
    assert result.has_errors is True
    quarantined = result.quarantined[0]
    assert quarantined.error_type == "MalformedEventError"
    # The raw payload is retained for auditing.
    assert quarantined.raw_payload is not None


def test_batch_strict_mode_raises(cloudtrail, normalizer):
    payload = {
        "Records": [
            cloudtrail("console_login_mfa.json"),
            cloudtrail("malformed_missing_eventname.json"),
        ]
    }
    with pytest.raises(MalformedEventError):
        normalizer.normalize_batch(payload, strict=True)


def test_batch_happy_path_normalizes_every_record(cloudtrail, normalizer):
    result = normalizer.normalize_batch(cloudtrail("s3_delivery_batch.json"))
    assert result.ok_count == 2
    assert result.error_count == 0
    families = {event.api_family for event in result.events}
    assert ApiFamilies.CONSOLE_SIGNIN in families
    assert ApiFamilies.CREDENTIAL_MANAGEMENT in families


def test_batch_size_limit_is_enforced(cloudtrail):
    from algo.detection.credential_compromise.config import DetectorConfig, IngestConfig

    config = DetectorConfig(ingest=IngestConfig(max_records_per_batch=1))
    normalizer = CloudTrailNormalizer(config)
    with pytest.raises(MalformedEventError):
        normalizer.normalize_batch(cloudtrail("s3_delivery_batch.json"))


def test_normalize_iter_is_lazy(cloudtrail, normalizer):
    records = [cloudtrail("console_login_mfa.json"), cloudtrail("s3_get_object.json")]
    events = list(normalizer.normalize_iter(records))
    assert len(events) == 2


def test_create_access_key_is_credential_management(cloudtrail, normalizer):
    record = cloudtrail("s3_delivery_batch.json")["Records"][1]
    event = normalizer.normalize(record)
    assert event.api_family == ApiFamilies.CREDENTIAL_MANAGEMENT
    assert event.privilege_change is True
