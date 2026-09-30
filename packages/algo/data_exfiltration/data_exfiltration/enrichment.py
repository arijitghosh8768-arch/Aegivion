"""External enrichment interfaces: geo/IP and Macie sensitivity.

Rules:

- Enrichment may only ADD information a source explicitly provides.
- Unknown lookups return None — nothing is inferred or defaulted.
- Sensitivity is external by definition; this engine never classifies
  content itself.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import Any, Protocol

from algo.data_exfiltration.data_exfiltration.measurement import (
    MeasurementConfidence,
    MeasurementSource,
    simple_measurement,
)
from algo.data_exfiltration.data_exfiltration.schemas import SensitivityLevel, _map_sensitivity_level

# Macie classification categories that map onto canonical sensitivity levels
_MACIE_CATEGORY_MAP = {
    "PERSONAL_INFORMATION": SensitivityLevel.PII,
    "HEALTH_INFORMATION": SensitivityLevel.PHI,
    "FINANCIAL_INFORMATION": SensitivityLevel.FINANCIAL,
    "CREDENTIALS": SensitivityLevel.SECRETS,
    "SENSITIVE_DATA_IDENTIFIERS": SensitivityLevel.CONFIDENTIAL,
}

_PUBLIC_SUFFIX_RE = re.compile(r"\.[a-z]{2,}$", re.IGNORECASE)


class GeoEnricher(Protocol):
    def lookup(self, ip: str) -> dict[str, str | None] | None: ...


class NullGeoEnricher:
    """Geo enrichment that never resolves anything (default)."""

    def lookup(self, ip: str) -> dict[str, str | None] | None:
        return None


class DictGeoEnricher:
    """Deterministic lookup over a static map — test/stub implementation."""

    def __init__(self, table: dict[str, dict[str, str | None]]) -> None:
        self._table = dict(table)

    def lookup(self, ip: str) -> dict[str, str | None] | None:
        return self._table.get(ip)


class MacieEnricher(Protocol):
    def lookup(self, bucket: str, key: str | None) -> dict[str, Any] | None: ...


class StaticMacieEnricher:
    """Deterministic Macie stub keyed by bucket/object prefix."""

    def __init__(self, table: dict[str, dict[str, Any]]) -> None:
        self._table = dict(table)

    def lookup(self, bucket: str, key: str | None) -> dict[str, Any] | None:
        if bucket in self._table:
            return self._table[bucket]
        for pattern, info in self._table.items():
            if pattern.endswith("/") and key and key.startswith(pattern):
                return info
        return None


def apply_macie_enrichment(event, enricher: MacieEnricher):
    """Attach Macie sensitivity to a normalized event, when available.

    Mutates and returns *event*. When Macie has no finding the event's
    sensitivity stays unavailable — never defaulted.
    """
    if event.bucket is None or enricher is None:
        return event
    info = enricher.lookup(event.bucket, event.object_key)
    if not info:
        return event

    level = _map_sensitivity_level(info.get("classification"))
    score = info.get("score")
    if level is None and score is None:
        return event

    event.sensitivity_level = level
    event.sensitivity_source = "macie"
    if score is not None:
        event.sensitivity_score = simple_measurement(
            float(score),
            MeasurementSource.MACIE,
            MeasurementConfidence.EXTERNAL_ENRICHMENT,
            detail=f"macie categories={info.get('categories') or []}",
        )
    return event


def macie_level_from_findings(findings: list[dict[str, Any]]) -> SensitivityLevel | None:
    """Map a list of Macie finding categories onto the canonical level."""
    levels: list[SensitivityLevel] = []
    for finding in findings:
        for category in finding.get("classificationDetails", {}).get("result", {}).get("customDataIdentifiers", {}).get(
            "detections", []
        ) or []:
            levels.append(SensitivityLevel.CONFIDENTIAL)
        for category in finding.get("classificationDetails", {}).get("result", {}).get(
            "sensitiveData", []
        ) or []:
            cat = str(category.get("category") or "")
            if cat in _MACIE_CATEGORY_MAP:
                levels.append(_MACIE_CATEGORY_MAP[cat])
    if not levels:
        return None
    # most severe wins; order matches escalation
    severity_order = [
        SensitivityLevel.SECRETS,
        SensitivityLevel.PHI,
        SensitivityLevel.FINANCIAL,
        SensitivityLevel.PII,
        SensitivityLevel.RESTRICTED,
        SensitivityLevel.CONFIDENTIAL,
        SensitivityLevel.INTERNAL,
        SensitivityLevel.PUBLIC,
        SensitivityLevel.NONE,
    ]
    return min(levels, key=severity_order.index)


def destination_domain_from_ip(ip: str | None) -> str | None:
    """Resolve an IP to a domain via reverse DNS.

    Deliberately NOT implemented in Part 1 — reverse resolution would be
    guessing. Callers wanting domains must supply them via enrichment.
    """
    return None


def is_public_destination(ip: str | None) -> bool | None:
    """True when *ip* is globally routable; False for RFC1918/link-local.

    Returns None when we cannot tell (no ip, malformed). We never claim a
    destination is 'external' without an address.
    """
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        a, b, _c, _d = (int(p) for p in parts)
    except ValueError:
        return None
    if a == 10 or a == 127 or a in (0,) or a > 223:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    return True


# ---------------------------------------------------------------------------
# Destination intelligence (Part 2)
# ---------------------------------------------------------------------------


class DestinationClass(str, Enum):
    """Destination classification. Novel does NOT mean malicious."""

    TRUSTED_INTERNAL = "trusted_internal"
    KNOWN_BUSINESS = "known_business"
    KNOWN_CLOUD = "known_cloud"
    UNKNOWN_EXTERNAL = "unknown_external"
    HIGH_RISK_EXTERNAL = "high_risk_external"
    UNAVAILABLE = "unavailable"


# Well-known anonymized attack-infrastructure networks (RFC 5737 ranges).
# Real deployments should load curated threat-intel CIDR lists instead.
HIGH_RISK_CIDRS = (
    "203.0.113.0/24",   # TEST-NET-3 (used here for exfil sim fixtures)
    "198.51.100.0/24",  # TEST-NET-2
    "192.0.2.0/24",     # TEST-NET-1
)

# ASN-number -> service identity for well-known cloud/business providers.
# Static bootstrap table; SaaS business services should be supplied via
# asset-inventory enrichment in real deployments.
ASN_SERVICE_MAP = {
    "16509": "aws",
    "14618": "aws",
    "8075": "microsoft",
    "15169": "google",
    "13335": "cloudflare",
    "54113": "netflix",  # example business service
}

_CLOUD_PROVIDERS = {"aws", "microsoft", "google", "cloudflare", "azure", "gcp", "oracle"}


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def normalize_destination(value: str | None) -> str | None:
    """Normalize a domain for comparison (lowercase, minus one subdomain
    level so ``s3-eu-west-1.amazonaws.com`` matches ``amazonaws.com``)."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip().lower().rstrip(".")
    if not text:
        return None
    labels = text.split(".")
    if len(labels) > 2 and len(labels[-1]) == 2 and len(labels[-2]) in (2, 3):
        # ccTLD second-level like co.uk / com.au
        return ".".join(labels[-3:])
    if len(labels) > 2:
        return ".".join(labels[-2:])
    return text


def classify_destination(
    *,
    ip: str | None = None,
    asn: str | None = None,
    country: str | None = None,
    domain: str | None = None,
    provider: str | None = None,
    known_destinations: set[str] | None = None,
    known_asns: set[str] | None = None,
    known_countries: set[str] | None = None,
    known_domains: set[str] | None = None,
    known_organizations: set[str] | None = None,
    known_business_services: set[str] | None = None,
    known_cloud_providers: set[str] | None = None,
) -> tuple[DestinationClass, str]:
    """Classify one destination; return (class, human reason).

    Precedence: high-risk CIDR/threat intel > trusted internal > known
    business/cloud (domain, ASN, org, provider) > unknown external.
    With no address or enrichment at all the class is UNAVAILABLE —
    never guessed.
    """
    norm_domain = normalize_destination(domain)

    if ip and any(_ip_in_cidr(ip, cidr) for cidr in HIGH_RISK_CIDRS):
        return DestinationClass.HIGH_RISK_EXTERNAL, f"ip in high-risk cidr {ip}"

    if ip is not None and is_public_destination(ip) is False:
        return DestinationClass.TRUSTED_INTERNAL, f"private address {ip}"

    if known_destinations and ip and ip in known_destinations:
        return DestinationClass.KNOWN_BUSINESS, f"ip {ip} in known destinations"

    if known_asns and asn and asn in known_asns:
        return DestinationClass.KNOWN_BUSINESS, f"asn {asn} known"

    if known_countries and country and country in known_countries:
        return DestinationClass.KNOWN_BUSINESS, f"country {country} known"

    if known_domains and norm_domain and norm_domain in known_domains:
        return DestinationClass.KNOWN_BUSINESS, f"domain {norm_domain} known"

    if known_organizations and provider and provider in known_organizations:
        return DestinationClass.KNOWN_BUSINESS, f"organization {provider} known"

    if known_business_services and provider and provider in known_business_services:
        return DestinationClass.KNOWN_BUSINESS, f"business service {provider} known"

    service = ASN_SERVICE_MAP.get(asn or "")
    if service:
        if known_cloud_providers and service in known_cloud_providers:
            return DestinationClass.KNOWN_CLOUD, f"asn {asn} -> {service} (approved cloud)"
        if service in _CLOUD_PROVIDERS:
            return DestinationClass.KNOWN_CLOUD, f"asn {asn} -> {service} (cloud provider)"
        return DestinationClass.KNOWN_BUSINESS, f"asn {asn} -> {service}"

    if provider and provider in _CLOUD_PROVIDERS:
        return DestinationClass.KNOWN_CLOUD, f"provider {provider}"

    if ip is not None and is_public_destination(ip) is True:
        return DestinationClass.UNKNOWN_EXTERNAL, f"public ip {ip} with no known attribution"

    return DestinationClass.UNAVAILABLE, "no address or attribution available"
