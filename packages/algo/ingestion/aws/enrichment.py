"""IP enrichment seam.

CloudTrail gives us ``sourceIPAddress`` but **not** country, ASN or geo hint.
Those require an enrichment provider. Aegivion must never invent them, so the
default implementation is :class:`NullIpEnricher`, which returns "unknown".

Wire a real provider (MaxMind GeoLite2, ipinfo, an internal service) by
implementing :class:`IpEnricher` and injecting it into the normalizer. Until
then the location/networking features correctly see ``None`` and treat them as
unknown rather than as an anomaly.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from detection.credential_compromise.schemas import IpIntelligence


@runtime_checkable
class IpEnricher(Protocol):
    """Turns a source IP into :class:`IpIntelligence`."""

    def enrich(self, ip: Optional[str]) -> IpIntelligence:
        ...


class NullIpEnricher:
    """Default enricher: knows nothing, invents nothing."""

    def enrich(self, ip: Optional[str]) -> IpIntelligence:
        return IpIntelligence()


class StaticIpEnricher:
    """Deterministic enricher for tests and offline evaluation.

    Maps known IPs (or CIDR-less prefixes) to fixed intelligence so evaluation
    runs are reproducible without network calls.
    """

    def __init__(self, mapping: Optional[dict[str, IpIntelligence]] = None) -> None:
        self._mapping = dict(mapping or {})

    def add(self, ip: str, intelligence: IpIntelligence) -> "StaticIpEnricher":
        self._mapping[ip] = intelligence
        return self

    def enrich(self, ip: Optional[str]) -> IpIntelligence:
        if not ip:
            return IpIntelligence()
        return self._mapping.get(ip, IpIntelligence())


__all__ = ["IpEnricher", "NullIpEnricher", "StaticIpEnricher"]
