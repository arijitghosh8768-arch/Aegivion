"""AWS API classifier tests."""

from __future__ import annotations

import pytest

from algo.detection.credential_compromise.schemas import AccessType, ApiFamilies, EventCategory
from algo.ingestion.aws.cloudtrail import AwsApiClassifier


@pytest.fixture
def classifier() -> AwsApiClassifier:
    return AwsApiClassifier()


@pytest.mark.parametrize(
    ("event_source", "expected"),
    [
        ("iam.amazonaws.com", "iam"),
        ("s3.amazonaws.com", "s3"),
        ("signin.amazonaws.com", "signin"),
        ("cloudtrail.amazonaws.com.cn", "cloudtrail"),
        ("", "unknown"),
    ],
)
def test_service_name_extraction(classifier, event_source, expected):
    assert classifier.service_name(event_source) == expected


@pytest.mark.parametrize(
    ("event_name", "expected"),
    [
        ("GetUser", AccessType.READ),
        ("ListBuckets", AccessType.READ),
        ("DescribeInstances", AccessType.READ),
        ("PutUserPolicy", AccessType.WRITE),
        ("CreateAccessKey", AccessType.WRITE),
        ("TerminateInstances", AccessType.WRITE),
        ("Frobnicate", AccessType.UNKNOWN),
    ],
)
def test_access_classification(classifier, event_name, expected):
    assert classifier.classify_access(event_name) is expected


def test_console_login_is_signin(classifier):
    result = classifier.classify("signin.amazonaws.com", "ConsoleLogin")
    assert result.api_family == ApiFamilies.CONSOLE_SIGNIN
    assert result.event_category is EventCategory.SIGNIN
    assert result.privilege_change is False


def test_iam_read_maps_to_iam_read_family(classifier):
    result = classifier.classify("iam.amazonaws.com", "GetUser")
    assert result.api_family == ApiFamilies.IAM_READ
    assert result.event_category is EventCategory.MANAGEMENT


def test_cloudtrail_tampering_is_flagged(classifier):
    result = classifier.classify("cloudtrail.amazonaws.com", "StopLogging")
    assert result.api_family == ApiFamilies.CLOUDTRAIL_TAMPER
    assert result.read_or_write is AccessType.WRITE


def test_guardduty_tampering_is_flagged(classifier):
    result = classifier.classify("guardduty.amazonaws.com", "DeleteDetector")
    assert result.api_family == ApiFamilies.GUARDDUTY_TAMPER


def test_secrets_management_vs_access(classifier):
    assert classifier.classify("secretsmanager.amazonaws.com", "GetSecretValue").api_family == (
        ApiFamilies.SECRETS_ACCESS
    )
    assert classifier.classify("secretsmanager.amazonaws.com", "PutSecretValue").api_family == (
        ApiFamilies.SECRETS_MANAGEMENT
    )


def test_kms_decrypt_is_crypto_family(classifier):
    result = classifier.classify("kms.amazonaws.com", "Decrypt")
    assert result.api_family == ApiFamilies.KMS_CRYPTO
    # Decrypt retrieves plaintext, so it is a read, not a write.
    assert result.read_or_write is AccessType.READ


def test_unknown_service_falls_back_to_generated_family(classifier):
    result = classifier.classify("some-new-service.amazonaws.com", "DoThing")
    assert result.api_family == "SOME-NEW-SERVICE_API"


def test_privilege_change_only_for_mutation_families(classifier):
    assert classifier.classify("iam.amazonaws.com", "AttachRolePolicy").privilege_change is True
    assert classifier.classify("iam.amazonaws.com", "GetRole").privilege_change is False
    assert classifier.classify("sts.amazonaws.com", "AssumeRole").privilege_change is False
