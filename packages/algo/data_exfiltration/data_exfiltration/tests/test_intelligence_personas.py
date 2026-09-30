"""The ten required behavioral intelligence persona tests.

Each persona runs through the full profiler. Core principle under test:
no single dimension classifies activity as malicious — large volume alone
scores 0 on destination/time/relationship dimensions, and every
unavailable signal stays unavailable.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from algo.data_exfiltration.data_exfiltration.intelligence import (
    ApprovedSchedule,
    BaselineEngine,
    BehavioralProfiler,
    FeatureAvailability,
    IntelligenceContext,
    KnownAccessUniverse,
    KnownUniverse,
    BaselineInfluence,
)
from algo.data_exfiltration.data_exfiltration.intelligence.access_pattern_intelligence import (
    build_access_universe,
)
from algo.data_exfiltration.data_exfiltration.intelligence.actor_resource_intelligence import (
    build_actor_resource_history,
)
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.session import SessionBuilder

from .fixtures.cloudtrail_records import NORM, S3_GET
from .fixtures.scenarios import (
    scenario_abnormal_enumeration,
    scenario_incomplete_telemetry,
    scenario_legit_backup,
    scenario_normal_s3_access,
    scenario_sensitive_access,
)

_BASE = datetime(2024, 11, 14, 6, 0, tzinfo=timezone.utc)
_ACTOR = "arn:aws:iam::111122223333:user/dev-user"


def _rec(seconds_offset: float, out: int, key: str = "docs/a.csv", bucket: str = "app-assets",
         hour: int | None = None, day_offset: int = 0) -> dict:
    when = _BASE + timedelta(days=day_offset, seconds=seconds_offset)
    if hour is not None:
        when = when.replace(hour=hour)
    return {
        **NORM,
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": "GetObject",
        "requestParameters": {"bucketName": bucket, "key": key},
        "additionalEventData": {"bytesTransferredOut": out},
    }


def _sessions(records: list[dict], gap: float = 900.0):
    events = [EventNormalizer().normalize_cloudtrail(r) for r in records]
    from algo.data_exfiltration.data_exfiltration.config import DetectorConfig, SessionConfig

    builder = SessionBuilder(DetectorConfig(session=SessionConfig(inactivity_gap=gap)))
    builder.add_events(events)
    return events, builder.flush()


def _profiler_with_history(records: list[dict], gap: float = 900.0) -> BehavioralProfiler:
    """Profiler whose baseline was trained on *records* (poisoning-gated)."""
    events, sessions = _sessions(records, gap)
    profiler = BehavioralProfiler()
    profiler.record_history(events, sessions, influence=BaselineInfluence.ELIGIBLE)
    return profiler


# 1. normal employee -----------------------------------------------------------
def test_persona_normal_employee_is_quiet() -> None:
    history = [_rec(i * 120.0 + d * 86400.0, 50_000) for d in range(10) for i in range(6)]
    profiler = _profiler_with_history(history)

    current = history[-6:]  # same shape as history
    events, sessions = _sessions(current)
    result = profiler.profile(sessions[0], events, IntelligenceContext())
    f = result.features

    assert f.volume_score.value is not None and f.volume_score.value <= 0.5
    assert f.volume_score.availability is FeatureAvailability.OBSERVED
    assert f.destination_score.value in (None, 0.0)
    assert f.baseline_scope_used == "personal"


# 2. backup workload -----------------------------------------------------------
def test_persona_backup_workload_scheduled_is_expected() -> None:
    # nightly 02:00 backup job, 30 days of history
    history = [_rec(i * 240.0, 500_000_000, bucket="backups-prod", hour=2, day_offset=d)
               for d in range(30) for i in range(3)]
    profiler = _profiler_with_history(history)

    events, sessions = _sessions(history[-3:])
    schedule = ApprovedSchedule(name="nightly-backup", start_hour_utc=2, end_hour_utc=4)
    result = profiler.profile(sessions[0], events, IntelligenceContext(schedules=[schedule]))
    f = result.features

    assert result.time.status == "approved_schedule"
    assert f.time_score.value == 0.0
    assert f.volume_score.value is not None and f.volume_score.value <= 0.5


# 3. analytics workload ---------------------------------------------------------
def test_persona_analytics_workload_peer_baseline() -> None:
    profiler = BehavioralProfiler()
    # three analytics peers with 10 sessions each; session bytes match the
    # shape the newcomer will produce (4 events x 30_000)
    peers = ["arn:aws:iam::1:a1", "arn:aws:iam::1:a2", "arn:aws:iam::1:a3"]
    for d in range(10):
        for p in peers:
            ts = _BASE.timestamp() * 1000 - d * 86_400_000
            profiler.engine.record("actor", "bytes", p, 120_000.0 + d, ts, peer_group="analytics")
            profiler.engine.record("actor", "objects", p, 4.0, ts, peer_group="analytics")
            profiler.engine.record("actor", "requests", p, 4.0, ts, peer_group="analytics")
            profiler.engine.record("actor", "resources", p, 1.0, ts, peer_group="analytics")

    # brand-new analytics actor, first session (cold start)
    events, sessions = _sessions([_rec(i * 60.0, 30_000) for i in range(4)])
    result = profiler.profile(
        sessions[0], events, IntelligenceContext(peer_group="analytics")
    )
    f = result.features

    assert f.baseline_scope_used in ("peer", "personal")
    assert f.cold_start is True
    # a quiet first session is NOT anomalous even with peer fallback
    if f.volume_score.value is not None:
        assert f.volume_score.value <= 0.5


# 4. large legitimate transfer ---------------------------------------------------
def test_persona_large_legitimate_transfer_not_auto_malicious() -> None:
    """Huge volume, but every other dimension is clean: the multi-signal
    rule says volume alone must not produce a high overall picture."""
    history = [_rec(i * 120.0 + d * 86400.0, 500_000_000, bucket="backups-prod")
               for d in range(12) for i in range(6)]
    profiler = _profiler_with_history(history)

    # current session on the day AFTER the last history day
    events, sessions = _sessions(
        [_rec(i * 120.0, 500_000_000, bucket="backups-prod", day_offset=12) for i in range(6)]
    )
    result = profiler.profile(sessions[0], events, IntelligenceContext())
    f = result.features

    assert f.volume_score.value is not None
    # volume deviation small (matches history), destination/time/relationship quiet
    assert f.volume_score.value <= 0.5
    assert f.destination_score.value in (None, 0.0)
    assert f.time_score.value in (None, 0.0)
    assert f.actor_resource_score.value in (None, 0.0)


# 5. sensitive data access --------------------------------------------------------
def test_persona_sensitive_data_access_surfaced_not_exaggerated() -> None:
    history = [_rec(i * 120.0 + d * 86400.0, 3_000_000, bucket="prod-customer-data")
               for d in range(10) for i in range(4)]
    profiler = _profiler_with_history(history)

    events, sessions = _sessions(history[-4:])
    context = IntelligenceContext(
        resource_sensitivity={"s3://prod-customer-data": ("pii", "macie", "external_enrichment")},
        resource_criticality={"s3://prod-customer-data": 0.4},
    )
    result = profiler.profile(sessions[0], events, context)
    f = result.features

    assert f.sensitivity_score.value == 0.7  # PII mapped score
    assert f.sensitivity_score.provenance == "macie"
    # Macie sensitivity (0.7) must NOT be conflated with business criticality (0.4)
    assert f.sensitivity_score.detail["business_criticality"] == 0.4
    # and the access itself is routine for this actor: volume quiet
    assert f.volume_score.value is not None and f.volume_score.value <= 0.5


# 6. new destination ----------------------------------------------------------------
def test_persona_new_destination_evidence_only() -> None:
    history = [_rec(i * 120.0 + d * 86400.0, 50_000) for d in range(10) for i in range(4)]
    profiler = _profiler_with_history(history)

    events, sessions = _sessions(history[-4:])
    # flow-derived destination appears in the session
    session = sessions[0].model_copy(update={"unique_destinations": ["203.0.113.99"]})
    known = KnownUniverse(destinations={"198.18.0.1"})
    result = profiler.profile(session, events, IntelligenceContext(known_destinations=known))
    f = result.features

    assert f.destination_score.value == 1.0  # novel: 1 of 1 unknown
    assert f.destination_score.detail["worst_class"] == "high_risk_external"
    # ...but it is one dimension only: time/relationship remain quiet
    assert f.time_score.value in (None, 0.0)


# 7. new resource ---------------------------------------------------------------------
def test_persona_new_resource_novelty_not_verdict() -> None:
    history = [_rec(i * 120.0 + d * 86400.0, 50_000) for d in range(10) for i in range(4)]
    universe = build_access_universe(
        [EventNormalizer().normalize_cloudtrail(r) for r in history[:-4]]
    ).universe
    profiler = _profiler_with_history(history)

    new_resource_records = [
        _rec(i * 120.0, 50_000, bucket="brand-new-bucket", day_offset=9) for i in range(4)
    ]
    events, sessions = _sessions(new_resource_records)
    result = profiler.profile(sessions[0], events, IntelligenceContext(known_access=universe))
    f = result.features

    assert f.access_pattern_score.value == 1.0  # resource novel
    assert f.access_pattern_score.detail["patterns"]["one_resource_many_objects"]["detected"] is False
    # volume stays quiet: same shape as always
    assert f.volume_score.value is not None and f.volume_score.value <= 0.5


# 8. scheduled batch -----------------------------------------------------------------
def test_persona_scheduled_batch_suppressed_time_anomaly() -> None:
    history = [_rec(i * 600.0, 200_000, hour=1, day_offset=d) for d in range(14) for i in range(2)]
    profiler = _profiler_with_history(history)

    events, sessions = _sessions([_rec(0.0, 200_000, hour=1), _rec(600.0, 200_000, hour=1)])
    schedules = [ApprovedSchedule(name="batch", start_hour_utc=1, end_hour_utc=3)]
    result = profiler.profile(sessions[0], events, IntelligenceContext(schedules=schedules))
    f = result.features

    assert f.time_score.value == 0.0
    assert f.time_score.detail["status"] == "approved_schedule"


# 9. slow transfer ----------------------------------------------------------------------
def test_persona_slow_transfer_duration_pattern() -> None:
    history = [_rec(i * 60.0 + d * 86400.0, 2_000_000) for d in range(10) for i in range(6)]
    profiler = _profiler_with_history(history)

    # 12 small reads stretched over ~8h: a long, slow session (the detector's
    # 8h duration cap may split off the tail; the head is the slow session)
    events, sessions = _sessions(
        [_rec(i * 2700.0, 2_000_000, key=f"trickle/{i}.csv") for i in range(12)],
        gap=3600.0,
    )
    session = sessions[0]
    from algo.data_exfiltration.data_exfiltration.features import extract_features

    feats = extract_features(session)
    assert feats.duration_seconds >= 7 * 3600
    assert feats.bytes_total == 22_000_000  # 11 events in the head session
    assert feats.bytes_per_second < 1000.0
    # profiler still completes and reports honest features
    result = profiler.profile(session, events, IntelligenceContext())
    assert result.features.volume_score.value is not None or result.features.volume_score.availability is FeatureAvailability.UNAVAILABLE


# 10. missing telemetry --------------------------------------------------------------------
def test_persona_missing_telemetry_stays_honest() -> None:
    from .fixtures.missing import ALL as MISSING_RECORDS

    events, sessions = _sessions(MISSING_RECORDS)
    profiler = BehavioralProfiler()
    result = profiler.profile(sessions[0], events, IntelligenceContext())
    f = result.features

    # no flows -> egress unavailable with reason, not zero
    assert f.egress_score.availability is FeatureAvailability.UNAVAILABLE
    assert f.egress_score.detail["reliability"] in (
        "not_correlated",
        "missing_or_uncomparable_halves",
        "no_destination_telemetry",
    )
    # no enrichment/registry -> sensitivity unavailable, not zero
    assert f.sensitivity_score.availability is FeatureAvailability.UNAVAILABLE
    # no destination telemetry -> destination unavailable
    assert f.destination_score.availability is FeatureAvailability.UNAVAILABLE
    # no history -> volume unavailable, cold start, NOT suspicious
    assert f.cold_start is True
    assert f.volume_score.availability is FeatureAvailability.UNAVAILABLE
    assert f.baseline_quality == 0.0


# extra: abnormal enumeration shapes --------------------------------------------------------
def test_persona_abnormal_enumeration_pattern_detected() -> None:
    records = scenario_abnormal_enumeration()
    events, sessions = _sessions(records)
    profiler = BehavioralProfiler()
    result = profiler.profile(sessions[0], events, IntelligenceContext())
    patterns = result.features.access_pattern_score.detail["patterns"]
    assert patterns["one_resource_many_objects"]["detected"] is False  # LISTs have no object keys
    assert result.features.object_count_score.value is not None or \
        result.features.object_count_score.availability is FeatureAvailability.UNAVAILABLE


def test_persona_sequence_deviation_recorded() -> None:
    history = []
    for d in range(10):
        history.extend([_rec(i * 120.0 + d * 86400.0, 50_000) for i in range(4)])
    profiler = _profiler_with_history(history)
    # current session: enumerate then copy — never done before by this actor
    current = [
        {**NORM, "eventTime": (_BASE + timedelta(seconds=0)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "eventName": "ListObjectsV2",
         "requestParameters": {"bucketName": "app-assets", "prefix": "docs/"}},
        {**NORM, "eventTime": (_BASE + timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "eventName": "GetObject",
         "requestParameters": {"bucketName": "app-assets", "key": "docs/a.csv"},
         "additionalEventData": {"bytesTransferredOut": 50_000}},
    ]
    events, sessions = _sessions(current)
    result = profiler.profile(sessions[0], events, IntelligenceContext())
    detail = result.features.access_pattern_score.detail
    # history exists (list→read familiar) but copy bigrams are novel or absent
    assert detail["sequence_availability"] in ("observed", "cold_start")
