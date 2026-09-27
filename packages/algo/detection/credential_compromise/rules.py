"""Configurable rule engine - **Part 2**.

Rules are *signals, never verdicts*: each rule inspects the event and the
extracted feature vector and, when its condition is met, emits a structured
:class:`RuleSignal` such as::

    {
        "rule_id": "R010",
        "signal": "privilege_modification",
        "severity": "high",
        "value": 1.0,
        "evidence": {...}
    }

Severities are configuration, not constants: :class:`RuleEngineConfig` can
re-severitied any rule, gate it behind a feature threshold, or disable it
outright. Confidence is inherited from the evidence baseline - a signal that
rests on a cold-start baseline carries that weakness forward.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

from detection.credential_compromise.config import BaselineConfig, FeatureConfig, RuleEngineConfig
from detection.credential_compromise.features import BehavioralFeatures, FeatureValue
from detection.credential_compromise.schemas import (
    ApiFamilies,
    IdentityActivityEvent,
    Severity,
)

VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class RuleSignal(BaseModel):
    """One structured rule hit, explainable by construction."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    signal: str
    severity: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    value: float = Field(ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "signal": self.signal,
            "severity": self.severity.lower(),
            "value": round(self.value, 4),
            "evidence": dict(self.evidence),
        }


class RuleDefinition(BaseModel):
    """A rule: id, emitted signal, default severity and its condition."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    rule_id: str
    signal: str
    severity: Severity
    threshold: float = Field(default=0.0, ge=0.0, le=1.0)
    condition: Callable[[IdentityActivityEvent, BehavioralFeatures], Optional[float]]
    description: str = ""
    #: Baseline-derived rules are suppressed when the evidence baseline is too
    #: weak (``FeatureConfig.min_feature_confidence``) so a cold-start identity
    #: cannot trigger a novelty signal storm. Event-intrinsic rules (privilege
    #: mutation, credential operations, MFA state) set this to ``False``.
    requires_baseline: bool = True

    def evaluate(
        self, event: IdentityActivityEvent, features: BehavioralFeatures
    ) -> Optional[float]:
        return self.condition(event, features)


# --------------------------------------------------------------------------- #
# Condition helpers - read the feature vector, never invent numbers
# --------------------------------------------------------------------------- #


def _feature(features: BehavioralFeatures, name: str) -> FeatureValue:
    return getattr(features, name)


def _new_country(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "country_novelty")
    if fv.value >= 1.0 and event.country:
        return 1.0
    return None


def _new_region(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "region_novelty")
    if fv.value >= 1.0 and (event.region_hint or event.region):
        return 1.0
    return None


def _new_ip(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "ip_novelty")
    if fv.value >= 1.0 and event.source_ip:
        corporate = bool(fv.evidence.get("corporate_range_hit"))
        # A new IP inside a corporate range is worth one signal, not panic.
        return 0.6 if corporate else 1.0
    return None


def _new_asn(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "asn_novelty")
    if fv.value >= 1.0 and event.asn is not None:
        return 1.0
    return None


def _unusual_hour(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "time_anomaly")
    if fv.value >= 0.7:
        return fv.value
    return None


def _new_client(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "client_novelty")
    if fv.value >= 1.0 and event.user_agent:
        return 1.0
    return None


def _rare_api(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "api_novelty")
    if fv.value >= 1.0 and event.api_family != ApiFamilies.DEFAULT:
        return 1.0
    return None


def _unusual_service(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "service_novelty")
    if fv.value >= 1.0:
        return 1.0
    return None


def _unusual_frequency(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "api_frequency_deviation")
    if fv.value >= 0.7:
        return fv.value
    return None


def _privilege_mutation(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "privilege_anomaly")
    if fv.value > 0 and fv.evidence.get("privilege_mutation"):
        return min(1.0, fv.value)
    return None


def _role_assumption(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "privilege_anomaly")
    role_context = event.role_arn or (
        fv.evidence.get("credential_operation")
    )
    if event.api_family == ApiFamilies.STS_SESSION and role_context:
        base = _feature(features, "api_novelty").value
        if base >= 0.5 or fv.value > 0:
            return max(0.7, fv.value)
    return None


def _access_key_anomaly(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "privilege_anomaly")
    if fv.evidence.get("credential_operation") and event.api_family in (
        ApiFamilies.CREDENTIAL_MANAGEMENT,
        ApiFamilies.IAM_PRIVILEGE_MUTATION,
    ):
        return min(1.0, max(0.7, fv.value))
    return None


def _mfa_anomaly(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "privilege_anomaly")
    if event.mfa_authenticated is False and fv.evidence.get("privilege_mutation"):
        return 1.0
    if event.mfa_authenticated is False and event.event_category.value == "signin":
        return 0.7
    return None


def _burst(event: IdentityActivityEvent, features: BehavioralFeatures) -> Optional[float]:
    fv = _feature(features, "api_frequency_deviation")
    if fv.value >= 0.9 and fv.evidence.get("z") is not None:
        return 1.0
    return None


# --------------------------------------------------------------------------- #
# The catalogue
# --------------------------------------------------------------------------- #

#: The initial rule catalogue. Ids are stable and referenced by findings.
RULE_CATALOGUE: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id="R001",
        signal="new_country",
        severity=Severity.MEDIUM,
        threshold=0.0,
        condition=_new_country,
        description="Activity from a country never observed for this identity.",
    ),
    RuleDefinition(
        rule_id="R002",
        signal="new_region",
        severity=Severity.LOW,
        threshold=0.0,
        condition=_new_region,
        description="Activity from a geographic region never observed before.",
    ),
    RuleDefinition(
        rule_id="R003",
        signal="new_ip",
        severity=Severity.LOW,
        threshold=0.0,
        condition=_new_ip,
        description="Source IP (or /24) never observed before.",
    ),
    RuleDefinition(
        rule_id="R004",
        signal="new_asn",
        severity=Severity.MEDIUM,
        threshold=0.0,
        condition=_new_asn,
        description="Source network (ASN) never observed before.",
    ),
    RuleDefinition(
        rule_id="R005",
        signal="unusual_activity_hour",
        severity=Severity.LOW,
        threshold=0.7,
        condition=_unusual_hour,
        description="Activity hour deviates strongly from the identity's own distribution.",
    ),
    RuleDefinition(
        rule_id="R006",
        signal="new_client",
        severity=Severity.LOW,
        threshold=0.0,
        condition=_new_client,
        description="Client / user agent never observed for this identity.",
    ),
    RuleDefinition(
        rule_id="R007",
        signal="rare_api",
        severity=Severity.MEDIUM,
        threshold=0.0,
        condition=_rare_api,
        description="API family never observed for this identity.",
    ),
    RuleDefinition(
        rule_id="R008",
        signal="unusual_service",
        severity=Severity.MEDIUM,
        threshold=0.0,
        condition=_unusual_service,
        description="Service never observed for this identity.",
    ),
    RuleDefinition(
        rule_id="R009",
        signal="unusual_api_frequency",
        severity=Severity.MEDIUM,
        threshold=0.7,
        condition=_unusual_frequency,
        description="API frequency deviates strongly from the identity's normal rate.",
    ),
    RuleDefinition(
        rule_id="R010",
        signal="privilege_modification",
        severity=Severity.HIGH,
        threshold=0.0,
        condition=_privilege_mutation,
        description="IAM/policy/permission mutation by this identity.",
        requires_baseline=False,
    ),
    RuleDefinition(
        rule_id="R011",
        signal="suspicious_role_assumption",
        severity=Severity.MEDIUM,
        threshold=0.0,
        condition=_role_assumption,
        description="Role assumption outside the identity's learned pattern.",
    ),
    RuleDefinition(
        rule_id="R012",
        signal="access_key_behavior_anomaly",
        severity=Severity.HIGH,
        threshold=0.0,
        condition=_access_key_anomaly,
        description="Access-key or credential operation outside the learned pattern.",
        requires_baseline=False,
    ),
    RuleDefinition(
        rule_id="R013",
        signal="mfa_state_anomaly",
        severity=Severity.HIGH,
        threshold=0.0,
        condition=_mfa_anomaly,
        description="Sensitive action performed without MFA where MFA is expected.",
        requires_baseline=False,
    ),
    RuleDefinition(
        rule_id="R014",
        signal="unusual_api_burst",
        severity=Severity.MEDIUM,
        threshold=0.9,
        condition=_burst,
        description="Exceptional burst of API activity versus the identity's normal rate.",
    ),
)

_CATALOGUE_INDEX: dict[str, RuleDefinition] = {rule.rule_id: rule for rule in RULE_CATALOGUE}

#: Baseline-derived features each rule's evidence rests on. The cold-start
#: gate reads these (not the whole vector) so event-intrinsic signals such as
#: privilege/MFA confidence can never un-suppress a novelty rule.
_RULE_PRIMARY_FEATURE: dict[str, tuple[str, ...]] = {
    "R001": ("country_novelty",),
    "R002": ("region_novelty",),
    "R003": ("ip_novelty",),
    "R004": ("asn_novelty",),
    "R005": ("time_anomaly",),
    "R006": ("client_novelty",),
    "R007": ("api_novelty",),
    "R008": ("service_novelty",),
    "R009": ("api_frequency_deviation",),
    "R011": ("api_novelty", "privilege_anomaly"),
    "R014": ("api_frequency_deviation",),
}


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


def evaluate_rules(
    event: IdentityActivityEvent,
    features: BehavioralFeatures,
    *,
    config: BaselineConfig,
    feature_config: Optional[FeatureConfig] = None,
    rule_config: Optional[RuleEngineConfig] = None,
    is_peer_baseline: bool = False,
) -> list[RuleSignal]:
    """Evaluate the rule catalogue for one event.

    Rules whose evidence rests on a low-confidence baseline are suppressed
    (see ``FeatureConfig.min_feature_confidence``): a cold-start identity does
    not trigger a signal storm on its first day. Disabling, re-severitied and
    re-thresholded rules are handled through :class:`RuleEngineConfig`.
    """
    feature_config = feature_config or FeatureConfig()
    rule_config = rule_config or RuleEngineConfig()

    signals: list[RuleSignal] = []
    for rule in RULE_CATALOGUE:
        if rule.rule_id in rule_config.disabled_rules:
            continue
        severity = Severity(
            rule_config.rule_severities.get(rule.rule_id, rule.severity.value).upper()
        )
        threshold = float(rule_config.rule_thresholds.get(rule.rule_id, rule.threshold))

        if rule.requires_baseline:
            # The gate must consider the features the rule actually reads, not
            # the strongest feature in the vector: privilege/MFA features carry
            # event-intrinsic confidence and would otherwise un-suppress the
            # baseline-derived novelty rules for cold-start identities.
            primary = _RULE_PRIMARY_FEATURE.get(rule.rule_id, ())
            confidences = [
                getattr(features, name).confidence
                for name in primary
                if getattr(features, name, None) is not None
            ]
            evidence_confidence = min(confidences) if confidences else 0.0
            if evidence_confidence < feature_config.min_feature_confidence:
                continue

        raw = rule.condition(event, features)
        if raw is None or raw < threshold:
            continue

        signals.append(
            RuleSignal(
                rule_id=rule.rule_id,
                signal=rule.signal,
                severity=severity.value,
                value=round(float(raw), 4),
                evidence={
                    "description": rule.description,
                    "baseline_quality": features.baseline_quality.value,
                    "is_peer_baseline": features.is_peer_baseline,
                },
            )
        )
    return signals


__all__ = [
    "RULE_CATALOGUE",
    "RuleDefinition",
    "RuleSignal",
    "evaluate_rules",
]
