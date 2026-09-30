"""Tests for the ML anomaly layer, temporal features, fusion and confidence."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from algo.detection.credential_compromise.anomaly import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    FeatureVector,
    IsolationForest,
    SupervisedAnomalyModel,
    build_feature_vector,
    identity_risk_context_value,
    mfa_anomaly_value,
    session_length_deviation_value,
)
from algo.detection.credential_compromise.config import (
    AnomalyConfig,
    DetectorConfig,
    FusionConfig,
    ScoringConfig,
)
from algo.detection.credential_compromise.confidence import (
    EvidenceContext,
    brier_score,
    evidence_confidence,
    expected_calibration_error,
    isotonic_calibrator,
    platt_scale,
)
from algo.detection.credential_compromise.exceptions import DetectionError
from algo.detection.credential_compromise.features import extract_features
from algo.detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    BaselineQuality,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    IdentitySession,
    PrincipalType,
)
from algo.detection.credential_compromise.scorer import (
    ComponentScores,
    rule_signal_score,
    score_event,
    severity_for,
)
from algo.detection.credential_compromise.temporal import (
    TemporalTracker,
    WindowStats,
    burst_score,
    temporal_anomaly_score,
    temporal_vector,
)

START = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
IDENTITY = "aws:111122223333:user:ml-test"


def make_event(seq: int, *, at: datetime | None = None, **overrides) -> IdentityActivityEvent:
    payload = dict(
        event_id=f"ml-{seq:05d}",
        timestamp=at or START,
        principal_id=IDENTITY,
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
        identity_key=IDENTITY,
        event_source="s3.amazonaws.com",
        event_name="GetObject",
        event_category=EventCategory.DATA,
        service_name="s3",
        api_family=ApiFamilies.S3_DATA_READ,
        read_or_write=AccessType.READ,
        source_ip="10.20.30.40",
        country="IN",
        asn=9829,
        user_agent="aws-cli/2.13.0",
        mfa_authenticated=True,
    )
    payload.update(overrides)
    return IdentityActivityEvent(**payload)


# --------------------------------------------------------------------------- #
# Feature vector
# --------------------------------------------------------------------------- #


def test_feature_vector_is_stable_and_ordered():
    config = ScoringConfig()
    event = make_event(1)
    from algo.detection.credential_compromise.features import BehavioralFeatures, FeatureValue

    def fv(name: str) -> FeatureValue:
        return FeatureValue(name=name, value=0.1, confidence=0.9)

    features = BehavioralFeatures(
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
    vector = build_feature_vector(
        event,
        features,
        windows={5: WindowStats(5), 15: WindowStats(15), 60: WindowStats(60), 1440: WindowStats(1440)},
        burst=0.0,
        config=config,
    )
    assert vector.as_dict() == dict(zip(FEATURE_NAMES, vector.values))
    assert len(vector.values) == 18
    # Missing session means that feature is explicitly recorded as missing.
    assert "session_length_deviation" in vector.missing


def test_mfa_and_session_and_context_values():
    event = make_event(2, mfa_authenticated=False, privilege_change=True)
    assert mfa_anomaly_value(event, None) == 1.0
    assert mfa_anomaly_value(make_event(3, mfa_authenticated=None), None) == 0.0

    session = IdentitySession(
        session_key="k",
        identity_key=IDENTITY,
        principal_id=IDENTITY,
        start_time=START,
        last_seen=START + timedelta(hours=6),
    )
    assert session_length_deviation_value(session) > 0.5
    assert session_length_deviation_value(None) == 0.0
    assert identity_risk_context_value(event, None, session) > 0.3


# --------------------------------------------------------------------------- #
# Isolation Forest
# --------------------------------------------------------------------------- #


def _cluster(rng: random.Random, center: tuple[float, ...], n: int, noise: float = 0.02):
    return [
        tuple(c + rng.uniform(-noise, noise) for c in center) for _ in range(n)
    ]


def test_forest_refuses_to_train_on_too_few_rows():
    forest = IsolationForest(AnomalyConfig(min_training_rows=64))
    with pytest.raises(DetectionError):
        forest.fit([(0.1, 0.2)] * 10)


def test_forest_separates_outliers_from_the_norm():
    rng = random.Random(7)
    normal = _cluster(rng, (0.1, 0.1, 0.1, 0.0, 0.1), 400, noise=0.05)
    forest = IsolationForest(AnomalyConfig(trees=50, subsample_size=128))
    forest.fit(normal)

    typical = normal[0]
    outlier = (0.95, 0.95, 0.95, 0.9, 0.95)
    assert forest.score(typical) < 0.2
    assert forest.score(outlier) > forest.score(typical)


def test_forest_is_deterministic_for_a_seed():
    rng = random.Random(11)
    rows = _cluster(rng, (0.2, 0.2, 0.2, 0.2, 0.2), 200)
    a = IsolationForest(AnomalyConfig(seed=5, trees=30)).fit(rows)
    b = IsolationForest(AnomalyConfig(seed=5, trees=30)).fit(rows)
    probe = (0.9, 0.1, 0.9, 0.1, 0.9)
    assert a.score(probe) == b.score(probe)


def test_unfitted_forest_refuses_to_score():
    forest = IsolationForest()
    with pytest.raises(DetectionError):
        forest.raw_score((0.1,) * 18)


# --------------------------------------------------------------------------- #
# Supervised slot honesty
# --------------------------------------------------------------------------- #


def test_supervised_model_tracks_synthetic_labels():
    rng = random.Random(3)
    rows = _cluster(rng, (0.2, 0.2, 0.2, 0.2, 0.2), 100)
    labels = [0] * 100
    model = SupervisedAnomalyModel(epochs=50).fit(
        rows, labels, synthetic=True, label_source="synthetic_dataset"
    )
    assert model.synthetic_labels is True
    assert model.label_source == "synthetic_dataset"
    with pytest.raises(DetectionError):
        SupervisedAnomalyModel().fit([(0.1,)], [])


# --------------------------------------------------------------------------- #
# Temporal windows
# --------------------------------------------------------------------------- #


def test_temporal_windows_are_causal():
    tracker = TemporalTracker()
    base = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    for i in range(5):
        tracker.observe(make_event(10 + i, at=base + timedelta(minutes=i)))
    stats = tracker.window_slices(IDENTITY, at=base + timedelta(minutes=4))
    assert stats[5].event_count == 5
    assert stats[15].event_count == 5
    # 24h window later sees the same events...
    later = tracker.window_slices(IDENTITY, at=base + timedelta(minutes=90))
    assert later[5].event_count == 0  # ...but the 5m window has moved on
    assert later[1440].event_count == 5


def test_burst_score_reacts_to_concentration():
    quiet_hour = WindowStats(window_minutes=60, event_count=10)
    calm_5m = WindowStats(window_minutes=5, event_count=1)
    bursty_5m = WindowStats(window_minutes=5, event_count=10)
    assert burst_score(calm_5m, quiet_hour) < 0.1  # in line with the hour's pace
    assert burst_score(bursty_5m, quiet_hour) > 0.5


def test_temporal_anomaly_score_privilege_burst():
    stats = {
        5: WindowStats(5, event_count=6, privilege_changes=2),
        15: WindowStats(15, event_count=6, privilege_changes=2),
        60: WindowStats(60, event_count=6),
        1440: WindowStats(1440, event_count=6),
    }
    assert temporal_anomaly_score(stats, burst=0.0) >= 0.8
    assert temporal_anomaly_score({m: WindowStats(m) for m in (5, 15, 60, 1440)}, burst=0.0) == 0.0


def test_temporal_vector_ordering_is_stable():
    stats = {5: WindowStats(5, event_count=1), 15: WindowStats(15, event_count=2)}
    first = temporal_vector(stats, burst=0.5)
    second = temporal_vector(dict(reversed(list(stats.items()))), burst=0.5)
    assert list(first) == list(second)


# --------------------------------------------------------------------------- #
# Fusion + confidence
# --------------------------------------------------------------------------- #


def test_fusion_weights_are_configured_not_averaged():
    config = FusionConfig(w_behavior=1.0, w_rule=0.0, w_anomaly=0.0, w_temporal=0.0, w_privilege=0.0)
    components = ComponentScores(behavior=0.5, rule=0.9, anomaly=0.9, temporal=0.9, privilege=0.9)
    result = score_event(components, config=config)
    # Only behavior contributes despite the other scores being high: weights
    # decide, not an average.
    assert result.risk == pytest.approx(50.0, abs=0.01)


def test_anomaly_is_discounted_by_configuration():
    config = FusionConfig()
    components = ComponentScores(behavior=0.0, rule=0.0, anomaly=1.0, temporal=0.0, privilege=0.0)
    result = score_event(components, config=config)
    assert result.risk == pytest.approx(
        100.0 * config.w_anomaly * config.anomaly_confidence_discount, abs=0.01
    )


def test_rule_signal_score_saturates():
    from algo.detection.credential_compromise.rules import RuleSignal

    ten_lows = [
        RuleSignal(rule_id=f"R{i:03d}", signal="s", severity="LOW", value=1.0)
        for i in range(10)
    ]
    assert rule_signal_score(ten_lows) == pytest.approx(0.5, abs=0.01)
    # Even a large stack of LOW signals saturates rather than compounding.
    many = [
        RuleSignal(rule_id=f"R{i:03d}", signal="s", severity="LOW", value=1.0)
        for i in range(30)
    ]
    assert rule_signal_score(many) <= 1.0
    assert rule_signal_score([]) == 0.0


def test_severity_uses_risk_and_confidence():
    # Strong evidence: high risk -> CRITICAL.
    assert severity_for(90.0, confidence=0.9, corroborating_signals=4) == "CRITICAL"
    # Weak evidence: same risk is capped.
    assert severity_for(90.0, confidence=0.2, corroborating_signals=0) == "MEDIUM"
    assert severity_for(10.0, confidence=1.0) == "LOW"


def test_confidence_is_not_risk_over_100():
    evidence = EvidenceContext(
        baseline_quality=BaselineQuality.GOOD,
        corroborating_signals=2,
        independent_dimensions_touched=2,
        enrichment_completeness=1.0,
    )
    confidence = evidence_confidence(evidence)
    assert confidence != 0.91  # arbitrary check: it is evidence-driven
    assert 0.0 < confidence <= 1.0
    # Peer baselines are weaker evidence than personal ones.
    peer = evidence.model_copy(update={"is_peer_baseline": True})
    assert evidence_confidence(peer) < confidence


def test_platt_and_isotonic_and_metrics():
    probs = [0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9]
    labels = [0, 0, 0, 0, 1, 1, 1, 1]
    a, b = platt_scale(probs, labels, epochs=300)
    assert a > 0
    calibrate = isotonic_calibrator(probs, labels)
    assert calibrate(0.05) <= calibrate(0.95)
    assert brier_score(probs, labels) < 0.25
    assert expected_calibration_error(probs, labels) <= 0.3
    with pytest.raises(ValueError):
        brier_score([0.5], [0, 1])
