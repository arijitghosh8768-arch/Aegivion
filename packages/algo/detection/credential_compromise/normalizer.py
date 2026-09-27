"""Provider-neutral normalization seam.

The detector only ever sees :class:`IdentityActivityEvent`. Which provider
produced it is decided here, by a registry of normalizers keyed on
:class:`CloudProvider`.

Part 1 ships **only** the AWS CloudTrail normalizer (in
``ingestion/aws/cloudtrail.py``). Azure Activity Logs and GCP Audit Logs are
added later by implementing :class:`ProviderNormalizer` and registering it - no
change to features, rules, scoring or storage.

Layering note: this module deliberately does **not** import the AWS adapter, so
detection stays independent of any provider.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

from .exceptions import UnsupportedEventSourceError
from .schemas import CloudProvider, IdentityActivityEvent


@runtime_checkable
class ProviderNormalizer(Protocol):
    """Contract every provider adapter must satisfy."""

    provider: CloudProvider

    def normalize(
        self,
        record: Any,
        *,
        raw_event_reference: Optional[str] = None,
    ) -> IdentityActivityEvent:
        ...


class NormalizerRegistry:
    """Maps a provider to its normalizer implementation."""

    def __init__(self) -> None:
        self._normalizers: dict[CloudProvider, ProviderNormalizer] = {}

    def register(self, normalizer: ProviderNormalizer) -> "NormalizerRegistry":
        self._normalizers[normalizer.provider] = normalizer
        return self

    def get(self, provider: CloudProvider) -> ProviderNormalizer:
        try:
            return self._normalizers[provider]
        except KeyError:
            raise UnsupportedEventSourceError(
                "no normalizer registered for this provider",
                provider=provider.value,
                context={"registered": sorted(p.value for p in self._normalizers)},
            ) from None

    def supports(self, provider: CloudProvider) -> bool:
        return provider in self._normalizers

    @property
    def providers(self) -> list[CloudProvider]:
        return sorted(self._normalizers, key=lambda p: p.value)

    def normalize(
        self,
        provider: CloudProvider,
        record: Any,
        *,
        raw_event_reference: Optional[str] = None,
    ) -> IdentityActivityEvent:
        return self.get(provider).normalize(
            record, raw_event_reference=raw_event_reference
        )


def default_registry() -> NormalizerRegistry:
    """A registry with the providers available in this build.

    The AWS adapter is imported lazily so that importing this module never
    pulls in provider code.
    """
    from ingestion.aws.cloudtrail import CloudTrailNormalizer

    normalizer = CloudTrailNormalizer()
    # ``CloudTrailNormalizer`` implements the protocol; ``provider`` is declared
    # explicitly here rather than on the class to keep the adapter free of
    # detection-layer imports.
    return NormalizerRegistry().register(_WithProvider(normalizer, CloudProvider.AWS))


class _WithProvider:
    """Adapter binding a concrete normalizer to its provider tag."""

    def __init__(self, inner: Any, provider: CloudProvider) -> None:
        self._inner = inner
        self.provider = provider

    def normalize(
        self,
        record: Any,
        *,
        raw_event_reference: Optional[str] = None,
    ) -> IdentityActivityEvent:
        return self._inner.normalize(record, raw_event_reference=raw_event_reference)


__all__ = [
    "NormalizerRegistry",
    "ProviderNormalizer",
    "default_registry",
]
