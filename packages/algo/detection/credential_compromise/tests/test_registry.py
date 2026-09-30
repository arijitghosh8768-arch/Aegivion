"""Normalizer registry tests."""

from __future__ import annotations

import pytest

from algo.detection.credential_compromise.exceptions import UnsupportedEventSourceError
from algo.detection.credential_compromise.normalizer import (
    NormalizerRegistry,
    default_registry,
)
from algo.detection.credential_compromise.schemas import CloudProvider


class FakeNormalizer:
    provider = CloudProvider.GCP

    def normalize(self, record, *, raw_event_reference=None):
        return {"record": record, "reference": raw_event_reference}


def test_registry_reports_supported_providers():
    registry = NormalizerRegistry().register(FakeNormalizer())
    assert registry.supports(CloudProvider.GCP) is True
    assert registry.supports(CloudProvider.AZURE) is False
    assert registry.providers == [CloudProvider.GCP]


def test_registry_rejects_unregistered_provider():
    with pytest.raises(UnsupportedEventSourceError):
        NormalizerRegistry().get(CloudProvider.AZURE)


def test_registry_delegates_normalization():
    registry = NormalizerRegistry().register(FakeNormalizer())
    result = registry.normalize(CloudProvider.GCP, {"a": 1}, raw_event_reference="ref-1")
    assert result == {"record": {"a": 1}, "reference": "ref-1"}


def test_fake_normalizer_satisfies_the_protocol():
    candidate = FakeNormalizer()
    # Structural check rather than isinstance(): runtime_checkable protocol
    # handling of data members varies across Python versions.
    assert hasattr(candidate, "provider")
    assert callable(candidate.normalize)


def test_default_registry_registers_aws_cloudtrail(cloudtrail):
    registry = default_registry()
    assert registry.supports(CloudProvider.AWS) is True

    event = registry.normalize(CloudProvider.AWS, cloudtrail("console_login_mfa.json"))
    assert event.provider is CloudProvider.AWS
    assert event.event_name == "ConsoleLogin"
