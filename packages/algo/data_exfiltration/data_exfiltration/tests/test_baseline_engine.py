"""Baseline engine + poisoning protection tests."""

from __future__ import annotations

from algo.data_exfiltration.data_exfiltration.config import BaselineEngineConfig
from algo.data_exfiltration.data_exfiltration.intelligence.baseline_engine import BaselineEngine
from algo.data_exfiltration.data_exfiltration.intelligence.baseline_guard import (
    BaselineInfluence,
    BaselinePoisoningPolicy,
)

_END = 1_800_000_000_000  # fixed "now" for determinism
_DAY = 86_400_000.0


def _engine(**kwargs) -> BaselineEngine:
    return BaselineEngine(BaselineEngineConfig(**kwargs))


def test_record_and_stats_personal() -> None:
    engine = _engine()
    for day in range(30):
        engine.record("actor", "bytes", "alice", 100.0 + day, _END - (29 - day) * _DAY)
    snap = engine.stats_for("actor", "bytes", "alice", end_epoch_ms=_END)
    assert snap is not None
    assert snap.source == "personal"
    assert len(snap.values) == 30
    assert snap.median is not None
    assert snap.p95 is not None
    assert snap.cold_start is False
    assert snap.baseline_quality == 1.0


def test_lookback_window_filtering() -> None:
    engine = _engine()
    for day in range(90):
        engine.record("actor", "bytes", "alice", 100.0, _END - day * _DAY)
    snap7 = engine.stats_for("actor", "bytes", "alice", lookback_seconds=7 * 86400, end_epoch_ms=_END)
    snap30 = engine.stats_for("actor", "bytes", "alice", lookback_seconds=30 * 86400, end_epoch_ms=_END)
    snap90 = engine.stats_for("actor", "bytes", "alice", lookback_seconds=90 * 86400, end_epoch_ms=_END)
    assert len(snap7.values) == 7
    assert len(snap30.values) == 30
    assert len(snap90.values) == 90


def test_cold_start_with_few_observations() -> None:
    engine = _engine(cold_start_max_observations=4)
    for i in range(3):
        engine.record("actor", "bytes", "newbie", 100.0, _END - i * _DAY)
    snap = engine.stats_for("actor", "bytes", "newbie", end_epoch_ms=_END)
    assert snap is not None
    assert snap.cold_start is True


def test_no_history_returns_none_not_zero() -> None:
    engine = _engine()
    assert engine.stats_for("actor", "bytes", "ghost", end_epoch_ms=_END) is None
    score, snap = engine.deviation("actor", "bytes", "ghost", 1e12, end_epoch_ms=_END)
    assert score == 0.0
    assert snap is None


def test_peer_fallback_for_cold_start() -> None:
    engine = _engine(cold_start_max_observations=2)
    for i in range(10):
        engine.record("actor", "bytes", "peer1", 100.0 + i, _END - i * _DAY, peer_group="analytics")
        engine.record("actor", "bytes", "peer2", 110.0 + i, _END - i * _DAY, peer_group="analytics")
        engine.record("actor", "bytes", "peer3", 90.0 + i, _END - i * _DAY, peer_group="analytics")
    engine.record("actor", "bytes", "newcomer", 500.0, _END, peer_group="analytics")

    score, snap = engine.deviation("actor", "bytes", "newcomer", 5000.0, end_epoch_ms=_END, peer_group="analytics")
    assert snap is not None
    assert snap.source == "peer"
    assert score > 0.0


def test_peer_baseline_excludes_self() -> None:
    engine = _engine(cold_start_max_observations=2)
    for i in range(10):
        engine.record("actor", "bytes", "peer1", 100.0, _END - i * _DAY, peer_group="g")
        engine.record("actor", "bytes", "peer2", 100.0, _END - i * _DAY, peer_group="g")
    # self observations wildly high; excluded from own peer comparison
    for i in range(10):
        engine.record("actor", "bytes", "newcomer", 1e9, _END - i * _DAY, peer_group="g")
    snap = engine.peer_stats("actor", "bytes", "g", end_epoch_ms=_END, exclude_entity="newcomer")
    assert snap is not None
    assert max(snap.values) < 1e6


def test_baseline_poisoning_blocked_risk_not_learned() -> None:
    engine = _engine()
    # 30 normal observations
    for day in range(30):
        engine.record("actor", "bytes", "alice", 100.0, _END - (31 - day) * _DAY)
    # attacker exfil: HIGH risk -> BLOCKED influence
    engine.record(
        "actor", "bytes", "alice", 1_000_000.0, _END,
        influence=BaselineInfluence.BLOCKED, risk="high",
    )
    snap = engine.stats_for("actor", "bytes", "alice", end_epoch_ms=_END)
    assert snap is not None
    assert max(snap.values) == 100.0  # blocked observation excluded
    # deviation still flags it against the clean baseline
    score, _ = engine.deviation("actor", "bytes", "alice", 1_000_000.0, end_epoch_ms=_END)
    assert score == 1.0


def test_baseline_poisoning_limited_risk_not_learned() -> None:
    engine = _engine()
    for day in range(30):
        engine.record("actor", "bytes", "bob", 100.0, _END - (31 - day) * _DAY)
    engine.record("actor", "bytes", "bob", 500.0, _END, influence=BaselineInfluence.LIMITED, risk="medium")
    snap = engine.stats_for("actor", "bytes", "bob", end_epoch_ms=_END)
    assert max(snap.values) == 100.0


def test_baseline_poisoning_policy_mapping() -> None:
    policy = BaselinePoisoningPolicy()
    assert policy.influence_for("low") is BaselineInfluence.ELIGIBLE
    assert policy.influence_for("medium") is BaselineInfluence.LIMITED
    assert policy.influence_for("high") is BaselineInfluence.BLOCKED
    # unknown labels are conservative
    assert policy.influence_for("unknown") is BaselineInfluence.LIMITED
    assert policy.can_shape_trusted("low") is True
    assert policy.can_shape_trusted("high") is False


def test_versioned_snapshot_changes_with_content() -> None:
    engine = _engine()
    v1 = engine.versioned_snapshot()
    engine.record("actor", "bytes", "alice", 1.0, _END)
    v2 = engine.versioned_snapshot()
    assert v1["version_id"] != v2["version_id"]
    assert v1["version_id"].startswith("bl-")


def test_all_nontrusted_observations_report_cold_start() -> None:
    engine = _engine()
    for i in range(10):
        engine.record("actor", "bytes", "mallory", 1e9, _END - i * _DAY, influence=BaselineInfluence.BLOCKED, risk="high")
    snap = engine.stats_for("actor", "bytes", "mallory", end_epoch_ms=_END)
    assert snap is not None
    assert snap.cold_start is True
    assert snap.values == []
    assert snap.baseline_quality == 0.0
