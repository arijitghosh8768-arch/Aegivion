"""Part 3 core tests: feature vector, temporal features, Isolation Forest."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    AvailableFeature,
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.feature_vector import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    build_feature_vector,
)
from algo.data_exfiltration.data_exfiltration.ml.isolation_forest import IsolationForest
from algo.data_exfiltration.data_exfiltration.ml.temporal import (
    TEMPORAL_WINDOWS,
    burst_and_slow_features,
    compute_temporal_features,
)
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.schemas import SensitivityLevel

from .fixtures.cloudtrail_records import NORM


def _fset(**overrides) -> BehavioralFeatureSet:
    fset = BehavioralFeatureSet(
        subject_id="actor-1",
        session_id="s-1",
        actor_id="actor-1",
        computed_at_epoch_ms=1_800_000_000_000,
    )
    for name in FEATURE_NAMES:
        pass
    fset.volume_score = AvailableFeature(value=0.2, availability=FeatureAvailability.OBSERVED)
    fset.object_count_score = AvailableFeature(value=0.1, availability=FeatureAvailability.OBSERVED)
    fset.request_rate_score = AvailableFeature(value=0.1, availability=FeatureAvailability.OBSERVED)
    fset.destination_score = AvailableFeature(
        value=0.5,
        availability=FeatureAvailability.OBSERVED,
        detail={"destination_novelty": 0.5, "asn_novelty": 0.0, "country_novelty": 0.0, "provider_novelty": None},
    )
    fset.access_pattern_score = AvailableFeature(
        value=0.3,
        availability=FeatureAvailability.OBSERVED,
        detail={"resource_novelty": 0.3, "prefix_novelty": 0.2, "access_diversity": 0.5,
                "access_sequence_score": 0.4},
    )
    fset.time_score = AvailableFeature(value=0.0, availability=FeatureAvailability.OBSERVED)
    fset.actor_resource_score = AvailableFeature(value=0.0, availability=FeatureAvailability.OBSERVED)
    fset.sensitivity_score = AvailableFeature(
        value=0.7,
        availability=FeatureAvailability.OBSERVED,
        provenance="macie",
        detail={"contributions": [{"score": 0.7, "source": "macie", "confidence": "external_enrichment"}]},
    )
    fset.egress_score = AvailableFeature(
        value=0.1,
        availability=FeatureAvailability.OBSERVED,
        detail={"network_egress_bytes": 1_000_000.0, "external_egress_ratio": 0.1},
    )
    for key, value in overrides.items():
        setattr(fset, key, value)
    return fset.finalize()


class TestFeatureVector:
    def test_all_features_present_in_frozen_order(self) -> None:
        vec = build_feature_vector(_fset())
        assert set(vec.values) == set(FEATURE_NAMES)
        ordered = vec.ordered_values()
        assert len(ordered) == len(FEATURE_NAMES)
        assert vec.availability_mask().count(1.0) == len(FEATURE_NAMES)
        assert vec.feature_version == FEATURE_VERSION

    def test_unavailable_features_are_none_not_zero(self) -> None:
        fset = _fset()
        fset.egress_score = AvailableFeature(availability=FeatureAvailability.UNAVAILABLE)
        vec = build_feature_vector(fset.finalize())
        assert vec.values["network_egress_bytes"] is None
        assert vec.values["external_egress_ratio"] is None
        assert vec.availability["network_egress_bytes"] == "unavailable"
        # masked to 0.0 in the ordered vector but flagged unavailable
        assert vec.ordered_values()[-2] == 0.0
        assert vec.availability_mask()[-2] == 0.0

    def test_sensitivity_confidence_from_contributions(self) -> None:
        vec = build_feature_vector(_fset())
        assert vec.values["sensitivity_confidence"] == 0.9  # external_enrichment

    def test_detail_keys_mapped(self) -> None:
        vec = build_feature_vector(_fset())
        assert vec.values["destination_novelty"] == 0.5
        assert vec.values["asn_novelty"] == 0.0
        assert vec.values["provider_novelty"] is None  # detail had None
        assert vec.values["access_sequence_score"] == 0.4
        assert vec.values["network_egress_bytes"] == 1_000_000.0


class TestTemporalFeatures:
    def _events(self) -> list:
        base = datetime(2024, 11, 14, 6, 0, tzinfo=timezone.utc)
        records = []
        for i in range(10):
            rec = {
                **NORM,
                "eventTime": (base + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventName": "GetObject",
                "requestParameters": {"bucketName": "b", "key": f"k{i}.csv"},
                "additionalEventData": {"bytesTransferredOut": 1000 * (i + 1)},
            }
            records.append(rec)
        return [EventNormalizer().normalize_cloudtrail(r) for r in records]

    def test_windows_covered(self) -> None:
        events = self._events()
        as_of = events[-1].event_time_epoch_ms
        tf = compute_temporal_features(events, as_of_epoch_ms=as_of)
        assert set(tf.cumulative_bytes) == {"5m", "15m", "1h", "6h", "24h"}
        assert len(TEMPORAL_WINDOWS) == 5

    def test_cumulative_counters(self) -> None:
        events = self._events()
        as_of = events[-1].event_time_epoch_ms
        tf = compute_temporal_features(events, as_of_epoch_ms=as_of)
        assert tf.cumulative_bytes["5m"] == 45000.0  # minutes 4..9: 5k+6k+7k+8k+9k+10k
        assert tf.cumulative_bytes["1h"] == 55000.0
        assert tf.cumulative_objects["1h"] == 10.0
        assert tf.unique_resources["1h"] == 1
        assert tf.unique_destinations["1h"] == 0

    def test_actor_filtering(self) -> None:
        events = self._events()
        events[0].actor_id = "someone-else"
        as_of = events[-1].event_time_epoch_ms
        tf = compute_temporal_features(events, as_of_epoch_ms=as_of, actor_id="arn:aws:iam::111122223333:user/dev-user")
        assert tf.cumulative_objects["1h"] == 9.0

    def test_sensitive_counters_require_enrichment(self) -> None:
        events = self._events()
        events[0].sensitivity_level = SensitivityLevel.PII
        events[0].sensitivity_source = "macie"
        as_of = events[-1].event_time_epoch_ms
        tf = compute_temporal_features(events, as_of_epoch_ms=as_of)
        assert tf.sensitive_objects["1h"] == 1.0
        assert tf.sensitive_bytes["1h"] == 1000.0

    def test_burst_and_slow(self) -> None:
        events = self._events()
        as_of = events[-1].event_time_epoch_ms
        tf = compute_temporal_features(events, as_of_epoch_ms=as_of)
        derived = burst_and_slow_features(tf)
        assert derived["burst_ratio"] is not None
        assert derived["slow_ratio"] is not None


class TestIsolationForest:
    def _training(self, n: int = 200) -> list[list[float]]:
        # deterministic synthetic cluster + outliers
        rows = []
        for i in range(n):
            if i % 10 == 0:
                rows.append([0.9, 0.9, 0.9, 0.9, 0.9, 0.0, 0.0, 0.9, 0.9, 0.9, 0.9, 0.5, 0.9, 0.1, 0.1, 0.9, 0.9])
            else:
                rows.append([0.05 + (i % 7) * 0.01, 0.05, 0.05, 0.1, 0.05, 0.0, 0.0, 0.0, 0.05, 0.05,
                             0.05, 0.0, 0.0, 0.1, 0.1, 0.0, 0.0])
        return rows

    def test_scores_in_unit_interval(self) -> None:
        model = IsolationForest(n_estimators=50, max_samples=64, seed=42)
        model.fit(self._training())
        for row in self._training(40):
            s = model.score(row)
            assert 0.0 <= s <= 1.0

    def test_outliers_score_higher(self) -> None:
        model = IsolationForest(n_estimators=50, max_samples=64, seed=42)
        rows = self._training()
        model.fit(rows)
        normal = rows[1]
        outlier = rows[0]
        assert model.score(outlier) >= model.score(normal)

    def test_deterministic_across_instances(self) -> None:
        rows = self._training()
        m1 = IsolationForest(n_estimators=30, max_samples=64, seed=42).fit(rows)
        m2 = IsolationForest(n_estimators=30, max_samples=64, seed=42).fit(rows)
        for row in rows[:20]:
            assert m1.score(row) == m2.score(row)

    def test_different_seed_changes_tie_breaks_only_not_range(self) -> None:
        rows = self._training()
        m1 = IsolationForest(n_estimators=30, seed=42).fit(rows)
        m2 = IsolationForest(n_estimators=30, seed=7).fit(rows)
        for row in rows[:10]:
            s1, s2 = m1.score(row), m2.score(row)
            assert 0.0 <= s1 <= 1.0 and 0.0 <= s2 <= 1.0

    def test_score_before_fit_raises(self) -> None:
        with pytest.raises(RuntimeError):
            IsolationForest().score([0.0] * 17)

    def test_feature_count_mismatch_raises(self) -> None:
        model = IsolationForest(n_estimators=10, seed=42).fit(self._training(30))
        with pytest.raises(ValueError):
            model.score([0.0] * 5)
