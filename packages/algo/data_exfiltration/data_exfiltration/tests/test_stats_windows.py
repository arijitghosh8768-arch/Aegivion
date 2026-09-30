"""Robust statistics + window aggregation tests (Part 2 primitives)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from algo.data_exfiltration.data_exfiltration.stats import (
    deviation_score,
    mad,
    median,
    modified_z_scores,
    percentile,
    ratio_log_growth,
    weighted_mean,
)
from algo.data_exfiltration.data_exfiltration.windows import aggregate_window
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer

from .fixtures.cloudtrail_records import S3_GET


def test_median_even_and_odd() -> None:
    assert median([1, 3, 5]) == 3.0
    assert median([1, 3, 5, 7]) == 4.0
    assert median([]) is None


def test_percentile_interpolation() -> None:
    assert percentile([10, 20, 30, 40], 50) == 25.0
    assert percentile([10, 20], 95) == 19.5
    assert percentile([], 50) is None


def test_mad_basic() -> None:
    # median 3, absolute deviations [2,1,0,1,2] -> mad 1
    assert mad([1, 2, 3, 4, 5]) == 1.0


def test_modified_z_robust_to_outliers() -> None:
    values = [10.0] * 9 + [1000.0]
    zs = modified_z_scores(values)
    assert zs is not None
    assert max(zs) < 3.5  # one outlier among many: MAD absorbs it


def test_deviation_score_no_history_is_zero() -> None:
    # absence of history is NEVER suspicious
    assert deviation_score(1e12, []) == 0.0


def test_deviation_score_within_gate() -> None:
    history = [100.0, 110.0, 90.0, 105.0, 95.0, 100.0, 108.0, 92.0]
    assert deviation_score(120.0, history) == 0.0


def test_deviation_score_extreme_observation() -> None:
    history = [100.0, 110.0, 90.0, 105.0, 95.0, 100.0, 108.0, 92.0]
    score = deviation_score(100_000.0, history)
    assert score == 1.0


def test_ratio_log_growth() -> None:
    assert ratio_log_growth(100, 100) == 0.0
    assert ratio_log_growth(400, 100) > 0.6
    assert ratio_log_growth(800, 100) == 1.0
    assert ratio_log_growth(50, 100) == 0.0
    assert ratio_log_growth(100, 0) == 0.0


def test_weighted_mean() -> None:
    assert weighted_mean([1.0, 2.0], [1.0, 3.0]) == 1.75
    assert weighted_mean([], []) is None
    assert weighted_mean([1.0], [0.0]) is None


# ---------------------------------------------------------------------------
# window aggregation
# ---------------------------------------------------------------------------

def _get(minute: int, out: int, key: str = "a.csv", actor: str | None = None) -> dict:
    t = datetime(2024, 11, 14, 3, minute, tzinfo=timezone.utc)
    rec = {**S3_GET, "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "requestParameters": {"bucketName": "b", "key": key},
           "additionalEventData": {"bytesTransferredOut": out}}
    if actor:
        rec["arn"] = actor
    return rec


def test_window_aggregation_slices() -> None:
    records = [_get(0, 100, key="a.csv"), _get(2, 100, key="b.csv"), _get(30, 100, key="c.csv")]
    events = [EventNormalizer().normalize_cloudtrail(r) for r in records]
    end = events[-1].event_time_epoch_ms

    # trailing 5-minute window from the LAST event: only the 03:30 event
    aggs_5m = aggregate_window(events, scope_fn=lambda e: e.actor_id, window_seconds=300, end_epoch_ms=end)
    five = aggs_5m["arn:aws:iam::111122223333:user/dev-user"]
    assert five.event_count == 1

    # trailing 5-minute window ending at the SECOND event: first two events
    end2 = events[1].event_time_epoch_ms
    aggs_5m_2 = aggregate_window(events, scope_fn=lambda e: e.actor_id, window_seconds=300, end_epoch_ms=end2)
    five2 = aggs_5m_2["arn:aws:iam::111122223333:user/dev-user"]
    assert five2.event_count == 2

    aggs_1h = aggregate_window(events, scope_fn=lambda e: e.actor_id, window_seconds=3600, end_epoch_ms=end)
    hour = aggs_1h["arn:aws:iam::111122223333:user/dev-user"]
    assert hour.event_count == 3
    assert hour.max_bytes == 300.0
    assert hour.objects_accessed == 3
    assert len(hour.unique_objects) == 3


def test_window_respects_scope_filtering() -> None:
    records = [_get(0, 100, actor="arn:aws:iam::1:user/a"), _get(1, 100, actor="arn:aws:iam::1:user/b")]
    events = [EventNormalizer().normalize_cloudtrail(r) for r in records]
    end = events[-1].event_time_epoch_ms
    aggs = aggregate_window(events, scope_fn=lambda e: e.actor_id, window_seconds=3600, end_epoch_ms=end)
    assert len(aggs) == 2
    assert all(a.event_count == 1 for a in aggs.values())


def test_empty_window_yields_zero_aggregate() -> None:
    records = [_get(0, 100)]
    events = [EventNormalizer().normalize_cloudtrail(r) for r in records]
    end = events[0].event_time_epoch_ms + 3_600_000  # 1h later
    aggs = aggregate_window(events, scope_fn=lambda e: e.actor_id, window_seconds=300, end_epoch_ms=end)
    assert aggs == {}
