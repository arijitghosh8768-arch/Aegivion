"""Behavioral feature extraction - **Part 2**.

Computes the six behavioral dimensions from one event against the effective
baseline chosen by ``baseline.select_effective_baseline``. Every feature is
normalised to ``0.0`` (normal) .. ``1.0`` (highly abnormal) and carries its own
evidence so any score can later be explained.

Reasoning principles encoded here:

* **One anomaly is not compromise.** Features are independent signals; fusing
  them is the scorer's job, not this module's.
* **Deviation, not rules of thumb.** Time anomaly is the event hour's
  deviation from the identity's own historical hourly distribution - "after
  midnight" is not malicious by itself.
* **Novelty is dampened, not weaponised.** A new country on a known corporate
  network is treated very differently from a new country on a new ASN.
* **Weak baselines degrade confidence, not scores.** When the identity's own
  history is thin we still report the observed-vs-expected comparison but mark
  the feature's evidence as low-confidence instead of inventing a verdict.
"""

from __future__ import annotations

import math
from typing import Any, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field

from detection.credential_compromise.baseline import (
    hour_key,
    ip_range_key,
    weekday_key,
)
from detection.credential_compromise.config import BaselineConfig, FeatureConfig
from detection.credential_compromise.schemas import (
    ApiFamilies,
    BaselineQuality,
    IdentityActivityEvent,
    IdentityProfile,
    PRIVILEGE_MUTATION_FAMILIES,
    ensure_utc,
)

# --------------------------------------------------------------------------- #
# Feature container
# --------------------------------------------------------------------------- #


class FeatureValue(BaseModel):
    """One measured feature: value, confidence and evidence."""

    model_config = ConfigDict(frozen=True)

    name: str
    value: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    observed: Any = None
    expected: Any = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    def to_evidence(self) -> dict[str, Any]:
        """Explainability-ready rendering of this feature."""
        return {
            "name": self.name,
            "value": round(self.value, 4),
            "confidence": round(self.confidence, 4),
            "observed": self.observed,
            "expected": self.expected,
            "evidence": dict(self.evidence),
        }


class BehavioralFeatures(BaseModel):
    """The six primary behavioral dimensions plus derived deviations."""

    model_config = ConfigDict(frozen=True)

    # 1. TIME
    time_anomaly: FeatureValue
    # 2. LOCATION
    country_novelty: FeatureValue
    region_novelty: FeatureValue
    location_anomaly: FeatureValue
    # 3. NETWORK
    ip_novelty: FeatureValue
    asn_novelty: FeatureValue
    network_reputation: FeatureValue
    network_anomaly: FeatureValue
    # 4. DEVICE / CLIENT
    client_novelty: FeatureValue
    device_anomaly: FeatureValue
    # 5. API BEHAVIOR
    api_novelty: FeatureValue
    service_novelty: FeatureValue
    api_frequency_deviation: FeatureValue
    read_write_deviation: FeatureValue
    api_sequence_deviation: FeatureValue
    api_anomaly: FeatureValue
    # 6. PRIVILEGE BEHAVIOR
    privilege_anomaly: FeatureValue

    baseline_quality: BaselineQuality = BaselineQuality.COLD_START
    is_peer_baseline: bool = False

    def dimension_values(self) -> dict[str, float]:
        """The six primary dimensions, for scoring and the anomaly model."""
        return {
            "time": self.time_anomaly.value,
            "location": self.location_anomaly.value,
            "ip": self.network_anomaly.value,
            "device": self.device_anomaly.value,
            "api": self.api_anomaly.value,
            "privilege": self.privilege_anomaly.value,
        }

    def all_features(self) -> dict[str, FeatureValue]:
        return {
            name: getattr(self, name)
            for name in type(self).model_fields
            if isinstance(getattr(self, name), FeatureValue)
        }

    def to_evidence(self) -> dict[str, Any]:
        """Explainability-ready dump of every feature."""
        return {
            "dimensions": self.dimension_values(),
            "features": {
                name: feature.to_evidence()
                for name, feature in self.all_features().items()
            },
            "baseline_quality": self.baseline_quality.value,
            "is_peer_baseline": self.is_peer_baseline,
        }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def novelty(probability: float, smoothing: float) -> float:
    """Map a historical probability to a novelty score in ``[0, 1]``.

    ``p = 1`` (the norm) -> 0; ``p = 0`` (never seen) -> 1; ``p = smoothing``
    -> 0.5. Rare-but-known behaviour scores strictly between the two.
    """
    if probability <= 0:
        return 1.0
    return smoothing / (probability + smoothing)


def distribution_probability(
    distribution: Optional[Mapping[str, float]],
    key: Optional[str],
) -> float:
    """The observed historical probability of ``key`` in a normalised dist.

    Keys are matched as strings: distributions persist JSON object keys (all
    strings), while event attributes like ``asn`` arrive as ints.
    """
    if not distribution or key is None:
        return 0.0
    total = sum(distribution.values())
    if total <= 0:
        return 0.0
    key_str = str(key)
    # Tolerate both normalised and raw-count distributions.
    if all(v <= 1.0 for v in distribution.values()):
        return float(distribution.get(key_str, 0.0))
    return float(distribution.get(key_str, 0.0)) / total


def _confidence_for(
    *,
    quality: BaselineQuality,
    event_count: int,
    min_events_for_personal: int,
    key_present: bool,
) -> float:
    """How much the detector trusts a baseline-derived comparison."""
    if not key_present:
        return 0.0  # nothing to compare - the feature abstains
    quality_floor = {
        BaselineQuality.EXCELLENT: 0.95,
        BaselineQuality.GOOD: 0.8,
        BaselineQuality.LIMITED: 0.5,
        BaselineQuality.COLD_START: 0.2,
    }[quality]
    # Thin histories are less trustworthy even when quality grading passed.
    depth = min(1.0, event_count / max(1, min_events_for_personal))
    return round(max(0.0, min(1.0, 0.5 * quality_floor + 0.5 * depth)), 4)


def _corporate_hit(event: IdentityActivityEvent, config: BaselineConfig) -> bool:
    if not event.source_ip or not config.corporate_networks:
        return False
    import ipaddress

    try:
        address = ipaddress.ip_address(event.source_ip)
    except ValueError:
        return False
    for cidr in config.corporate_networks:
        if address in ipaddress.ip_network(cidr, strict=False):
            return True
    return False


def _maintenance_hit(event: IdentityActivityEvent, config: BaselineConfig) -> bool:
    return any(window.covers(ensure_utc(event.timestamp)) for window in config.maintenance_windows)


# --------------------------------------------------------------------------- #
# Dimension extractors
# --------------------------------------------------------------------------- #


def _time_features(
    event: IdentityActivityEvent,
    profile: Optional[IdentityProfile],
    config: BaselineConfig,
    feature_config: FeatureConfig,
    confidence: float,
) -> tuple[FeatureValue, FeatureValue, FeatureValue]:
    """Returns ``(hour_novelty, weekday_novelty, time_anomaly)``."""
    hour = hour_key(event)
    weekday = weekday_key(event)
    hour_p = distribution_probability(profile.normal_hours if profile else None, hour)
    weekday_p = distribution_probability(profile.normal_days if profile else None, weekday)

    hour_novelty = novelty(hour_p, feature_config.novelty_smoothing)
    weekday_novelty = novelty(weekday_p, feature_config.novelty_smoothing)

    in_maintenance = _maintenance_hit(event, config)
    maintenance_evidence: dict[str, Any] = {}
    if in_maintenance:
        hour_novelty = min(hour_novelty, 0.3)
        maintenance_evidence["maintenance_window_active"] = True

    time_value = max(hour_novelty, weekday_novelty * 0.6)
    return (
        FeatureValue(
            name="time_hour_novelty",
            value=round(hour_novelty, 4),
            confidence=confidence,
            observed=hour,
            expected=f"p={round(hour_p, 4)}",
            evidence={"weekend_factor_applied": weekday_novelty * 0.6 > hour_novelty},
        ),
        FeatureValue(
            name="time_weekday_novelty",
            value=round(weekday_novelty, 4),
            confidence=confidence,
            observed=weekday,
            expected=f"p={round(weekday_p, 4)}",
            evidence={},
        ),
        FeatureValue(
            name="time_anomaly",
            value=round(time_value, 4),
            confidence=confidence,
            observed={"hour": hour, "weekday": weekday},
            expected={
                "hour_distribution": dict(profile.normal_hours) if profile else {},
                "day_distribution": dict(profile.normal_days) if profile else {},
            },
            evidence=maintenance_evidence,
        ),
    )


def _location_features(
    event: IdentityActivityEvent,
    profile: Optional[IdentityProfile],
    feature_config: FeatureConfig,
    confidence: float,
) -> tuple[FeatureValue, FeatureValue, FeatureValue]:
    country = event.country
    region = event.region_hint or event.region
    # A missing geo key must abstain (0.0), not score as "novel": unenriched
    # telemetry is a measurement gap, not evidence of travel.
    country_novelty_value = (
        novelty(
            distribution_probability(profile.normal_countries if profile else None, country),
            feature_config.novelty_smoothing,
        )
        if country
        else 0.0
    )
    region_novelty_value = (
        novelty(
            distribution_probability(profile.normal_regions if profile else None, region),
            feature_config.novelty_smoothing,
        )
        if region
        else 0.0
    )

    location_value = max(country_novelty_value, 0.7 * region_novelty_value)
    return (
        FeatureValue(
            name="country_novelty",
            value=round(country_novelty_value, 4),
            confidence=confidence,
            observed=country,
            expected=f"p={round(distribution_probability(profile.normal_countries if profile else None, country), 4)}",
            evidence={} if country else {"country_missing": True},
        ),
        FeatureValue(
            name="region_novelty",
            value=round(region_novelty_value, 4),
            confidence=confidence,
            observed=region,
            expected=f"p={round(distribution_probability(profile.normal_regions if profile else None, region), 4)}",
            evidence={} if region else {"region_missing": True},
        ),
        FeatureValue(
            name="location_anomaly",
            value=round(location_value, 4),
            confidence=confidence,
            observed={"country": country, "region": region},
            expected={
                "countries": dict(profile.normal_countries) if profile else {},
                "regions": dict(profile.normal_regions) if profile else {},
            },
            evidence={"travel_is_not_compromise": True},
        ),
    )


def _network_features(
    event: IdentityActivityEvent,
    profile: Optional[IdentityProfile],
    config: BaselineConfig,
    feature_config: FeatureConfig,
    confidence: float,
) -> tuple[FeatureValue, FeatureValue, FeatureValue, FeatureValue]:
    ip_range = ip_range_key(event)
    range_p = distribution_probability(profile.normal_ip_ranges if profile else None, ip_range)
    asn_p = distribution_probability(profile.normal_asns if profile else None, event.asn)

    # Missing network telemetry abstains rather than scoring as novel.
    ip_novelty_value = (
        novelty(range_p, feature_config.novelty_smoothing) if event.source_ip else 0.0
    )
    asn_novelty_value = (
        novelty(asn_p, feature_config.novelty_smoothing) if event.asn is not None else 0.0
    )

    corporate = _corporate_hit(event, config)
    reputation = 0.0
    reputation_evidence: dict[str, Any] = {}
    if corporate:
        reputation = 0.1
        reputation_evidence["corporate_range"] = True
    if event.asn is not None and asn_p == 0:
        reputation = max(reputation, 0.4)
        reputation_evidence["unknown_asn"] = event.asn

    # A new IP inside a known corporate range is routine; the same new IP on a
    # novel ASN is the pattern that deserves attention.
    dampener = 0.35 if corporate else 1.0
    network_value = max(
        ip_novelty_value * dampener,
        asn_novelty_value * (0.5 if corporate else 1.0),
        reputation,
    )
    return (
        FeatureValue(
            name="ip_novelty",
            value=round(ip_novelty_value, 4),
            confidence=confidence,
            observed=event.source_ip,
            expected={"range": ip_range, "p": round(range_p, 4)},
            evidence={"corporate_range_hit": corporate}
            if event.source_ip
            else {"ip_missing": True},
        ),
        FeatureValue(
            name="asn_novelty",
            value=round(asn_novelty_value, 4),
            confidence=confidence,
            observed=event.asn,
            expected=f"p={round(asn_p, 4)}",
            evidence={} if event.asn is not None else {"asn_missing": True},
        ),
        FeatureValue(
            name="network_reputation",
            value=round(reputation, 4),
            confidence=confidence,
            observed={"corporate": corporate, "asn": event.asn},
            expected="corporate_ranges",
            evidence=reputation_evidence,
        ),
        FeatureValue(
            name="network_anomaly",
            value=round(network_value, 4),
            confidence=confidence,
            observed={"ip": event.source_ip, "asn": event.asn},
            expected={
                "ip_ranges": dict(profile.normal_ip_ranges) if profile else {},
                "asns": dict(profile.normal_asns) if profile else {},
            },
            evidence=reputation_evidence,
        ),
    )


def _client_features(
    event: IdentityActivityEvent,
    profile: Optional[IdentityProfile],
    feature_config: FeatureConfig,
    confidence: float,
) -> tuple[FeatureValue, FeatureValue]:
    ua_p = distribution_probability(
        profile.normal_user_agents if profile else None, event.user_agent
    )
    # No user agent at all is a telemetry gap, not a novel client.
    client_novelty_value = (
        novelty(ua_p, feature_config.novelty_smoothing) if event.user_agent else 0.0
    )
    return (
        FeatureValue(
            name="client_novelty",
            value=round(client_novelty_value, 4),
            confidence=confidence,
            observed=event.user_agent,
            expected=f"p={round(ua_p, 4)}",
            evidence={} if event.user_agent else {"user_agent_missing": True},
        ),
        FeatureValue(
            name="device_anomaly",
            value=round(client_novelty_value, 4),
            confidence=confidence,
            observed=event.user_agent,
            expected=dict(profile.normal_user_agents) if profile else {},
            evidence={} if event.user_agent else {"user_agent_missing": True},
        ),
    )


def _api_features(
    event: IdentityActivityEvent,
    profile: Optional[IdentityProfile],
    feature_config: FeatureConfig,
    confidence: float,
    session_rate: Optional[float],
) -> tuple[FeatureValue, FeatureValue, FeatureValue, FeatureValue, FeatureValue, FeatureValue]:
    family_p = distribution_probability(
        profile.normal_api_families if profile else None, event.api_family
    )
    service_p = distribution_probability(profile.normal_services if profile else None, event.service_name)
    api_novelty_value = novelty(family_p, feature_config.novelty_smoothing)
    service_novelty_value = novelty(service_p, feature_config.novelty_smoothing)

    # Frequency deviation: current session rate vs the identity's average.
    frequency_value = 0.0
    frequency_evidence: dict[str, Any] = {}
    if session_rate is not None and profile and profile.avg_events_per_hour > 0:
        std = profile.std_events_per_hour or max(1.0, 0.25 * profile.avg_events_per_hour)
        z = abs(session_rate - profile.avg_events_per_hour) / std
        frequency_value = 1.0 - math.exp(-z / feature_config.frequency_zscore_squash)
        frequency_evidence = {
            "z": round(z, 4),
            "observed_rate": round(session_rate, 4),
            "expected_rate": round(profile.avg_events_per_hour, 4),
        }

    # Read/write deviation: how far the observed access type sits from the
    # identity's expected write share. deviation = |observed - expected|.
    rw_value = 0.0
    rw_evidence: dict[str, Any] = {}
    if profile and profile.event_count > 0 and event.read_or_write.value in ("read", "write"):
        ratio = profile.read_write_ratio or 0.0
        expected_write_share = 0.0 if math.isinf(ratio) else 1.0 / (1.0 + max(0.0, ratio))
        observed_write = 1.0 if event.read_or_write.value == "write" else 0.0
        rw_value = min(1.0, abs(observed_write - expected_write_share))
        rw_evidence = {
            "expected_write_share": round(expected_write_share, 4),
            "historical_read_write_ratio": None if math.isinf(ratio) else ratio,
        }

    # Sequence deviation (deterministic v1 heuristic): a privilege mutation
    # right after a session-establishment family. The full learned
    # sequence model arrives with the ML layer; this is intentionally
    # conservative and configurable.
    sequence_value = 0.0
    sequence_evidence: dict[str, Any] = {}
    if feature_config.enable_sequence_heuristic and event.privilege_change:
        session_families = {
            ApiFamilies.CONSOLE_SIGNIN,
            ApiFamilies.SSO,
            ApiFamilies.STS_SESSION,
        }
        if event.api_family in session_families:
            sequence_value = 0.5
            sequence_evidence = {
                "pattern": "privilege_change_during_session_establishment",
                "api_family": event.api_family,
            }

    api_value = max(
        api_novelty_value,
        0.8 * service_novelty_value,
        frequency_value,
        0.6 * rw_value,
        0.7 * sequence_value,
    )
    return (
        FeatureValue(
            name="api_novelty",
            value=round(api_novelty_value, 4),
            confidence=confidence,
            observed=event.api_family,
            expected=f"p={round(family_p, 4)}",
            evidence={},
        ),
        FeatureValue(
            name="service_novelty",
            value=round(service_novelty_value, 4),
            confidence=confidence,
            observed=event.service_name,
            expected=f"p={round(service_p, 4)}",
            evidence={},
        ),
        FeatureValue(
            name="api_frequency_deviation",
            value=round(frequency_value, 4),
            confidence=confidence,
            observed=session_rate,
            expected=profile.avg_events_per_hour if profile else 0.0,
            evidence=frequency_evidence,
        ),
        FeatureValue(
            name="read_write_deviation",
            value=round(rw_value, 4),
            confidence=confidence,
            observed=event.read_or_write.value,
            expected=profile.read_write_ratio if profile else 0.0,
            evidence=rw_evidence,
        ),
        FeatureValue(
            name="api_sequence_deviation",
            value=round(sequence_value, 4),
            confidence=confidence,
            observed=event.api_family,
            expected="learned_sequences_part_of_ml_layer",
            evidence=sequence_evidence,
        ),
        FeatureValue(
            name="api_anomaly",
            value=round(api_value, 4),
            confidence=confidence,
            observed={"family": event.api_family, "service": event.service_name},
            expected={
                "families": dict(profile.normal_api_families) if profile else {},
                "services": dict(profile.normal_services) if profile else {},
            },
            evidence={**frequency_evidence, **rw_evidence, **sequence_evidence},
        ),
    )


def _privilege_feature(
    event: IdentityActivityEvent,
    profile: Optional[IdentityProfile],
    config: BaselineConfig,
    feature_config: FeatureConfig,
    confidence: float,
) -> FeatureValue:
    privilege_mutation = event.privilege_change or event.api_family in PRIVILEGE_MUTATION_FAMILIES
    credential_operation = event.api_family == ApiFamilies.CREDENTIAL_MANAGEMENT
    base = 0.0
    evidence: dict[str, Any] = {}
    if privilege_mutation:
        base = 0.8
        evidence["privilege_mutation"] = True
    if credential_operation:
        base = max(base, 0.7)
        evidence["credential_operation"] = True
    if event.api_family == ApiFamilies.IAM_PRIVILEGE_MUTATION:
        base = max(base, 0.85)
        evidence["iam_policy_mutation"] = True

    level = profile.normal_privilege_level if profile else "UNKNOWN"
    dampener = feature_config.privilege_level_dampening.get(
        level, feature_config.privilege_level_dampening.get("UNKNOWN", 0.9)
    )
    value = base * dampener if base else 0.0
    # Whether a privilege mutation *happened* is intrinsic to the event and
    # does not depend on the baseline, so the evidence keeps full confidence
    # even for cold-start identities. (The dampener still reflects context.)
    feature_confidence = 1.0 if base > 0 else confidence
    return FeatureValue(
        name="privilege_anomaly",
        value=round(value, 4),
        confidence=feature_confidence,
        observed={
            "privilege_change": event.privilege_change,
            "api_family": event.api_family,
        },
        expected=f"level={level}",
        evidence=evidence,
    )


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def extract_features(
    event: IdentityActivityEvent,
    profile: Optional[IdentityProfile],
    *,
    config: BaselineConfig,
    feature_config: Optional[FeatureConfig] = None,
    is_peer_baseline: bool = False,
    session_rate: Optional[float] = None,
) -> BehavioralFeatures:
    """Extract the six behavioral dimensions for one event.

    ``profile`` is the *effective* baseline (personal or merged peer). ``None``
    means the detector has no baseline at all: every baseline-derived feature
    abstains (value 0, confidence 0) rather than fabricating an anomaly.
    """
    feature_config = feature_config or FeatureConfig()

    if profile is None:
        abstain = FeatureValue(name="abstain", value=0.0, confidence=0.0)
        return BehavioralFeatures(
            time_anomaly=abstain.model_copy(update={"name": "time_anomaly"}),
            country_novelty=abstain.model_copy(update={"name": "country_novelty"}),
            region_novelty=abstain.model_copy(update={"name": "region_novelty"}),
            location_anomaly=abstain.model_copy(update={"name": "location_anomaly"}),
            ip_novelty=abstain.model_copy(update={"name": "ip_novelty"}),
            asn_novelty=abstain.model_copy(update={"name": "asn_novelty"}),
            network_reputation=abstain.model_copy(update={"name": "network_reputation"}),
            network_anomaly=abstain.model_copy(update={"name": "network_anomaly"}),
            client_novelty=abstain.model_copy(update={"name": "client_novelty"}),
            device_anomaly=abstain.model_copy(update={"name": "device_anomaly"}),
            api_novelty=abstain.model_copy(update={"name": "api_novelty"}),
            service_novelty=abstain.model_copy(update={"name": "service_novelty"}),
            api_frequency_deviation=abstain.model_copy(
                update={"name": "api_frequency_deviation"}
            ),
            read_write_deviation=abstain.model_copy(update={"name": "read_write_deviation"}),
            api_sequence_deviation=abstain.model_copy(
                update={"name": "api_sequence_deviation"}
            ),
            api_anomaly=abstain.model_copy(update={"name": "api_anomaly"}),
            privilege_anomaly=_privilege_feature(
                event, None, config, feature_config, confidence=0.0
            ),
            baseline_quality=BaselineQuality.COLD_START,
            is_peer_baseline=False,
        )

    confidence = _confidence_for(
        quality=profile.baseline_quality,
        event_count=profile.event_count,
        min_events_for_personal=config.min_events_for_personal_baseline,
        key_present=True,
    )

    hour_novelty, weekday_novelty, time_anomaly = _time_features(
        event, profile, config, feature_config, confidence
    )
    country_novelty, region_novelty, location_anomaly = _location_features(
        event, profile, feature_config, confidence
    )
    ip_novelty, asn_novelty, network_reputation, network_anomaly = _network_features(
        event, profile, config, feature_config, confidence
    )
    client_novelty, device_anomaly = _client_features(event, profile, feature_config, confidence)
    (
        api_novelty,
        service_novelty,
        api_frequency_deviation,
        read_write_deviation,
        api_sequence_deviation,
        api_anomaly,
    ) = _api_features(event, profile, feature_config, confidence, session_rate)
    privilege_anomaly = _privilege_feature(
        event, profile, config, feature_config, confidence
    )

    return BehavioralFeatures(
        time_anomaly=time_anomaly,
        country_novelty=country_novelty,
        region_novelty=region_novelty,
        location_anomaly=location_anomaly,
        ip_novelty=ip_novelty,
        asn_novelty=asn_novelty,
        network_reputation=network_reputation,
        network_anomaly=network_anomaly,
        client_novelty=client_novelty,
        device_anomaly=device_anomaly,
        api_novelty=api_novelty,
        service_novelty=service_novelty,
        api_frequency_deviation=api_frequency_deviation,
        read_write_deviation=read_write_deviation,
        api_sequence_deviation=api_sequence_deviation,
        api_anomaly=api_anomaly,
        privilege_anomaly=privilege_anomaly,
        baseline_quality=profile.baseline_quality,
        is_peer_baseline=is_peer_baseline,
    )


__all__ = [
    "BehavioralFeatures",
    "FeatureValue",
    "distribution_probability",
    "extract_features",
    "novelty",
]
