"""Tests for risk fusion, severity banding and the behavior-layer score."""

from __future__ import annotations

import pytest

from detection.credential_compromise.config import ScoringConfig
from detection.credential_compromise.features import BehavioralFeatures, FeatureValue
from detection.credential_compromise.rules import RuleSignal
from detection.credential_compromise.schemas import Severity
from detection.credential_compromise.scorer import (
    ComponentScores,
    calculate_risk,
    rule_signal_score,
    score_event,
    severity_for,
)

#: Feature confidence used by ``make_features`` - the score discounts by it.
CONF = 0.9


def make_features(**overrides: float) -> BehavioralFeatures:
    quiet = {
        "time_anomaly": 0.0,
        "country_novelty": 0.0,
        "region_novelty": 0.0,
        "location_anomaly": 0.0,
        "ip_novelty": 0.0,
        "asn_novelty": 0.0,
        "network_reputation": 0.0,
        "network_anomaly": 0.0,
        "client_novelty": 0.0,
        "device_anomaly": 0.0,
        "api_novelty": 0.0,
        "service_novelty": 0.0,
        "api_frequency_deviation": 0.0,
        "read_write_deviation": 0.0,
        "api_sequence_deviation": 0.0,
        "api_anomaly": 0.0,
        "privilege_anomaly": 0.0,
    }
    quiet.update(overrides)

    def fv(name: str) -> FeatureValue:
        return FeatureValue(name=name, value=quiet[name], confidence=CONF)

    return BehavioralFeatures(
        time_anomaly=fv("time_anomaly"),
        country_novelty=fv("country_novelty"),
        region_novelty=fv("region_novelty"),
        location_anomaly=fv("location_anomaly"),
        ip_novelty=fv("ip_novelty"),
        asn_novelty=fv("asn_novelty"),
        network_reputation=fv("network_reputation"),
        network_anomaly=fv("network_anomaly"),
        client_novelty=fv("client_novelty"),
        device_anomaly=fv("device_anomaly"),
        api_novelty=fv("api_novelty"),
        service_novelty=fv("service_novelty"),
        api_frequency_deviation=fv("api_frequency_deviation"),
        read_write_deviation=fv("read_write_deviation"),
        api_sequence_deviation=fv("api_sequence_deviation"),
        api_anomaly=fv("api_anomaly"),
        privilege_anomaly=fv("privilege_anomaly"),
    )


def signal(severity: str, rule_id: str = "R010") -> RuleSignal:
    return RuleSignal(rule_id=rule_id, signal="x", severity=severity, value=1.0)


def test_all_quiet_event_scores_zero():
    assert calculate_risk(make_features()) == 0.0


def test_weighted_mean_is_confidence_discounted():
    features = make_features(location_anomaly=1.0, network_anomaly=1.0)
    weights = ScoringConfig().weights
    expected = 100.0 * (weights["location"] + weights["ip"]) * CONF
    assert calculate_risk(features) == pytest.approx(expected, abs=0.01)


def test_signal_boost_is_bounded_and_takes_max():
    features = make_features(api_anomaly=0.4)
    base = calculate_risk(features)
    boosted = calculate_risk(
        features,
        [signal("HIGH", "R010"), signal("MEDIUM", "R007")],
    )
    config = ScoringConfig()
    assert boosted == pytest.approx(
        min(100.0, base + config.signal_boost["HIGH"]), abs=0.01
    )
    # Boost reflects the most severe signal only - no unbounded stacking.
    triple = calculate_risk(
        features,
        [signal("HIGH", "R010"), signal("HIGH", "R012"), signal("HIGH", "R013")],
    )
    assert triple == boosted


def test_critical_signal_boost():
    features = make_features(time_anomaly=0.6)
    config = ScoringConfig()
    risk = calculate_risk(features, [signal("CRITICAL", "R013")], config=config)
    # weighted mean (time only) = 0.15 * 0.6 * CONF; the boost is added after
    # the mean, unscaled, and the total is capped at 100.
    expected = min(100.0, 100.0 * (0.15 * 0.6 * CONF + config.signal_boost["CRITICAL"] / 100.0))
    assert risk == pytest.approx(expected, abs=0.01)


def test_risk_is_capped_at_100():
    features = make_features(
        time_anomaly=1.0,
        location_anomaly=1.0,
        network_anomaly=1.0,
        device_anomaly=1.0,
        api_anomaly=1.0,
        privilege_anomaly=1.0,
    )
    risk = calculate_risk(features, [signal("CRITICAL")])
    assert risk == 100.0


def test_ensemble_fusion_uses_configured_weights():
    config = FusionConfigForTest.all_on_behavior()
    components = ComponentScores(behavior=0.5, rule=0.9, anomaly=0.9, temporal=0.9, privilege=0.9)
    result = score_event(components, config=config)
    # Weights decide, not an average: only behavior contributes here.
    assert result.risk == pytest.approx(50.0, abs=0.01)


def test_anomaly_component_is_discounted():
    config = FusionConfigForTest.default()
    components = ComponentScores(behavior=0.0, rule=0.0, anomaly=1.0, temporal=0.0, privilege=0.0)
    result = score_event(components, config=config)
    assert result.risk == pytest.approx(
        100.0 * config.w_anomaly * config.anomaly_confidence_discount, abs=0.01
    )


def test_rule_signal_score_saturates_without_full_stack():
    lows = [
        RuleSignal(rule_id=f"R{i:03d}", signal="s", severity="LOW", value=1.0)
        for i in range(10)
    ]
    assert rule_signal_score(lows) == pytest.approx(0.5, abs=0.01)
    assert rule_signal_score([]) == 0.0
    # Even a large stack of LOW signals cannot masquerade as a certain hit.
    many = [
        RuleSignal(rule_id=f"R{i:03d}", signal="s", severity="LOW", value=1.0)
        for i in range(40)
    ]
    assert rule_signal_score(many) <= 1.0


def test_severity_uses_risk_confidence_and_evidence():
    # Strong evidence: high risk -> CRITICAL.
    assert severity_for(90.0, confidence=0.9, corroborating_signals=4) is Severity.CRITICAL
    assert severity_for(70.0, confidence=0.9, corroborating_signals=2) is Severity.HIGH
    assert severity_for(35.0, confidence=0.9, corroborating_signals=1) is Severity.MEDIUM
    # Weak evidence caps severity regardless of the raw risk number.
    assert severity_for(90.0, confidence=0.2, corroborating_signals=0) is Severity.MEDIUM
    assert severity_for(10.0, confidence=1.0, corroborating_signals=0) is Severity.LOW


class FusionConfigForTest:
    """Small adapters so tests read clearly."""

    @staticmethod
    def default():
        from detection.credential_compromise.config import FusionConfig

        return FusionConfig()

    @staticmethod
    def all_on_behavior():
        from detection.credential_compromise.config import FusionConfig

        return FusionConfig(
            w_behavior=1.0, w_rule=0.0, w_anomaly=0.0, w_temporal=0.0, w_privilege=0.0
        )
