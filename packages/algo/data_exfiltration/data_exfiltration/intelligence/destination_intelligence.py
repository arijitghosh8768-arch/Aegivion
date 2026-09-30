"""Destination intelligence: novelty shares and classification.

Novelty is measured against a supplied known-universe (from asset
inventory, resource profiles, or enrichment). When the universe for a
dimension is not supplied, that novelty is explicitly unavailable —
"we don't know what's normal" is never treated as "this is malicious".
A new destination is evidence to review, not a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from algo.data_exfiltration.data_exfiltration.enrichment import (
    DestinationClass,
    ASN_SERVICE_MAP,
    classify_destination,
    is_public_destination,
    normalize_destination,
)
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession


@dataclass
class KnownUniverse:
    """What the organization already knows about destinations.

    ``None`` means "not supplied" (novelty cannot be judged); an explicit
    empty set means "supplied, nothing known" (everything public is
    novel — still not automatically malicious).
    """

    destinations: set[str] | None = None
    asns: set[str] | None = None
    countries: set[str] | None = None
    domains: set[str] | None = None
    organizations: set[str] | None = None
    business_services: set[str] | None = None
    cloud_providers: set[str] | None = None
    providers_by_ip: dict[str, str] = field(default_factory=dict)
    """Optional attribution (e.g. from DNS/CMDB): ip -> provider/org name."""


_CLASS_SEVERITY = [
    DestinationClass.HIGH_RISK_EXTERNAL,
    DestinationClass.UNKNOWN_EXTERNAL,
    DestinationClass.KNOWN_CLOUD,
    DestinationClass.KNOWN_BUSINESS,
    DestinationClass.TRUSTED_INTERNAL,
    DestinationClass.UNAVAILABLE,
]


class DestinationAssessment(BaseModel):
    session_id: str
    destinations: list[dict[str, Any]] = Field(default_factory=list)
    destination_novelty: float | None = None
    asn_novelty: float | None = None
    country_novelty: float | None = None
    provider_novelty: float | None = None
    class_counts: dict[str, int] = Field(default_factory=dict)
    worst_class: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


def _novelty_share(values: set[str] | list[str], known: set[str] | None, *, internal_check=None) -> float | None:
    """Share of *values* absent from *known*.

    None when the universe is not supplied (cannot judge novelty).
    Internal/private values are exempt from novelty by default.
    """
    if known is None:
        return None
    if not values:
        return 0.0
    candidates = [
        v for v in values
        if internal_check is None or internal_check(v) is not False
    ]
    if not candidates:
        return 0.0
    novel = [v for v in candidates if v not in known]
    return round(len(novel) / len(candidates), 4)


def assess_destinations(
    session: DataAccessSession,
    known: KnownUniverse | None = None,
) -> DestinationAssessment:
    """Classify every destination and compute novelty shares."""
    known = known or KnownUniverse()
    assessment = DestinationAssessment(session_id=session.session_id)

    class_counts: dict[str, int] = {}
    worst: DestinationClass | None = None

    for ip in session.unique_destinations:
        provider = known.providers_by_ip.get(ip)
        cls, reason = classify_destination(
            ip=ip,
            provider=provider,
            known_destinations=known.destinations,
            known_organizations=known.organizations,
            known_business_services=known.business_services,
            known_cloud_providers=known.cloud_providers,
        )
        class_counts[cls.value] = class_counts.get(cls.value, 0) + 1
        if worst is None or _CLASS_SEVERITY.index(cls) < _CLASS_SEVERITY.index(worst):
            worst = cls
        assessment.destinations.append({
            "ip": ip,
            "class": cls.value,
            "reason": reason,
            "provider": provider,
        })

    # session-level asns/countries classification context
    for asn in session.unique_asns:
        cls, reason = classify_destination(asn=asn, known_asns=known.asns)
        class_counts[cls.value] = class_counts.get(cls.value, 0) + 1
        if worst is None or _CLASS_SEVERITY.index(cls) < _CLASS_SEVERITY.index(worst):
            worst = cls

    for country in session.unique_countries:
        cls, reason = classify_destination(country=country, known_countries=known.countries)
        class_counts[cls.value] = class_counts.get(cls.value, 0) + 1
        if worst is None or _CLASS_SEVERITY.index(cls) < _CLASS_SEVERITY.index(worst):
            worst = cls

    assessment.class_counts = class_counts
    assessment.worst_class = worst.value if worst is not None else None

    public_only = [d for d in session.unique_destinations if is_public_destination(d) is True]
    assessment.destination_novelty = _novelty_share(
        public_only, known.destinations, internal_check=is_public_destination
    )
    assessment.asn_novelty = _novelty_share(session.unique_asns, known.asns)
    assessment.country_novelty = _novelty_share(session.unique_countries, known.countries)
    providers = {
        known.providers_by_ip[ip]
        for ip in session.unique_destinations
        if ip in known.providers_by_ip
    }
    assessment.provider_novelty = _novelty_share(
        providers, known.organizations or known.business_services or known.cloud_providers
    ) if providers else (None if not known.providers_by_ip else 0.0)

    assessment.detail = {
        "known_universe_supplied": {
            "destinations": known.destinations is not None,
            "asns": known.asns is not None,
            "countries": known.countries is not None,
            "providers": bool(known.organizations or known.business_services),
        },
        "asn_services": [ASN_SERVICE_MAP.get(a) for a in session.unique_asns if a in ASN_SERVICE_MAP],
    }
    return assessment
