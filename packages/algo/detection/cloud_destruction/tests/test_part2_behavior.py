"""Part 2 behavioral-layer tests: baselines, analyzers, features, context.

Covers the Part 2 deliverables end to end with deterministic expectations:

- deviation math and evidence collection,
- per-actor baselines with quality and versioning,
- baseline poisoning defense (LOW/MEDIUM/HIGH/CRITICAL ladder),
- modification / deletion / versioning / snapshot / backup analyzers,
- recovery destruction, protection degradation, recoverability,
- rewrite-transform chains (content-neutral naming discipline),
- temporal analysis (bursts, slow destruction) and sequences,
- approved-activity context (auditable, scoped, reversible, time-aware),
- extract_features integration, no-verdict invariants, provenance.

No ML anywhere: every expectation below is hand-computed.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from detection.cloud_destruction.baseline import (
    BaselineConfig,
    BaselineContamination,
    BaselineQuality,
    BaselineStore,
    build_baseline,
    classify_contamination,
    measure_novelty,
)
from detection.cloud_destruction.backup import analyze_backup
from detection.cloud_destruction.config import BehavioralConfig, DestructionDetectorConfig
from detection.cloud_destruction.deletion import analyze_deletion
from detection.cloud_destruction.deviation import clamp01, ratio_to_factor
from detection.cloud_destruction.evidence import collect_evidence
from detection.cloud_destruction.features import SessionFeatureVector, extract_features
from detection.cloud_destruction.legitimate import (
    ActivityContext,
    ApprovedActivityProfile,
    match_profile,
)
from detection.cloud_destruction.modification import analyze_modification
from detection.cloud_destruction.provenance import DataProvenance
from detection.cloud_destruction.recoverability import analyze_recoverability
from detection.cloud_destruction.rewrite import analyze_rewrite
from detection.cloud_destruction.sequence import analyze_sequences
from detection.cloud_destruction.session import DestructiveSessionBuilder
from detection.cloud_destruction.snapshot import analyze_snapshots
from detection.cloud_destruction.schemas import (
    ActionCategory,
    BusinessCriticality,
    DestructiveActivitySession,
    ResourceActivityEvent,
)
from detection.cloud_destruction.temporal import analyze_temporal
from detection.cloud_destruction.versioning import analyze_versioning

from detection.cloud_destruction.tests.helpers import BASE_TIME, make_event

# --------------------------------------------------------------------------- #
# Event/session factories
# --------------------------------------------------------------------------- #


def delete_event(event_id: str, **overrides) -> ResourceActivityEvent:
    return make_event(
        event_id=event_id, action_category=ActionCategory.DELETE,
        raw_action="s3:DeleteObject", **overrides,
    )


def write_event(event_id: str, **overrides) -> ResourceActivityEvent:
    return make_event(
        event_id=event_id, action_category=ActionCategory.CREATE,
        raw_action="s3:PutObject", **overrides,
    )


def read_event(event_id: str, **overrides) -> ResourceActivityEvent:
    return make_event(
        event_id=event_id, action_category=ActionCategory.READ,
        raw_action="s3:GetObject", **overrides,
    )


def rewrite_event(event_id: str, **overrides) -> ResourceActivityEvent:
    return make_event(
        event_id=event_id, action_category=ActionCategory.REWRITE,
        raw_action="s3:CopyObject", **overrides,
    )


def version_delete_event(event_id: str, **overrides) -> ResourceActivityEvent:
    return make_event(
        event_id=event_id, action_category=ActionCategory.VERSION_DELETE,
        raw_action="s3:DeleteObjectVersion", **overrides,
    )


def snapshot_delete_event(event_id: str, **overrides) -> ResourceActivityEvent:
    return make_event(
        event_id=event_id, action_category=ActionCategory.SNAPSHOT_DELETE,
        raw_action="ec2:DeleteSnapshot", **overrides,
    )


def vault_delete_event(event_id: str, **overrides) -> ResourceActivityEvent:
    return make_event(
        event_id=event_id, action_category=ActionCategory.BACKUP_DELETE,
        raw_action="backup:DeleteBackupVault", **overrides,
    )


def protection_event(event_id: str, **overrides) -> ResourceActivityEvent:
    return make_event(
        event_id=event_id, action_category=ActionCategory.PROTECTION_CHANGE,
        raw_action="s3:PutBucketVersioning", **overrides,
    )


def hist_session(
    actor: str,
    n_events: int,
    seconds: float = 30.0,
    start=BASE_TIME,
    category: ActionCategory = ActionCategory.READ,
    categories: list[ActionCategory] | None = None,
):
    """Build one benign-ish history session of ``n_events`` for ``actor``."""
    cats = categories or [category]
    events = []
    for i in range(n_events):
        events.append(
            make_event(
                event_id=f"{actor}-{cats[i % len(cats)].value}-{i:03d}",
                timestamp=start + timedelta(seconds=seconds * i),
                actor_id=actor,
                action_category=cats[i % len(cats)],
            )
        )
    session = DestructiveSessionBuilder().build_sessions(events)[0]
    return session, events


def mass_session(n: int = 50, start=BASE_TIME, seconds: float = 5.0, actor: str = "attacker"):
    """Build one mass-deletion session over ``n`` distinct resources."""
    events = []
    for i in range(n):
        events.append(
            delete_event(
                f"del-{i:03d}",
                timestamp=start + timedelta(seconds=seconds * i),
                actor_id=actor,
                resource_id=f"fin-prod-archive-{i}",
                resource_arn=f"arn:aws:s3:::fin-prod-archive-{i}/obj",
            )
        )
    session = DestructiveSessionBuilder().build_sessions(events)[0]
    return session, events


def match_events(sessions, events):
    """Replicate extract_features' event->session matching for direct tests."""
    event_by_id = {e.event_id: e for e in events}
    out = []
    for s in sessions:
        matched = [event_by_id[e] for e in s.event_ids if e in event_by_id]
        out.append((s, matched))
    return out


def run_analyzers(session, events, baseline=None, cfg=None):
    bcfg = cfg or BehavioralConfig()
    ev = collect_evidence(session, events or None)
    return {
        "evidence": ev,
        "mod": analyze_modification(session, baseline, config=bcfg, evidence=ev),
        "del": analyze_deletion(session, baseline, config=bcfg, evidence=ev),
        "ver": analyze_versioning(session, baseline, config=bcfg, evidence=ev),
        "snap": analyze_snapshots(session, baseline, config=bcfg, evidence=ev),
        "bak": analyze_backup(session, baseline, config=bcfg, evidence=ev),
        "rec": analyze_recoverability(session, baseline, config=bcfg, evidence=ev),
        "rew": analyze_rewrite(session, baseline, config=bcfg, evidence=ev),
        "seq": analyze_sequences(session, baseline, config=bcfg, evidence=ev),
        "tmp": analyze_temporal(session, baseline, config=bcfg, evidence=ev),
    }


# --------------------------------------------------------------------------- #
# 1. Deviation math
# --------------------------------------------------------------------------- #


class TestDeviationMath:
    def test_clamp01(self):
        assert clamp01(-1.0) == 0.0
        assert clamp01(0.5) == 0.5
        assert clamp01(2.0) == 1.0

    def test_ratio_to_factor_zero_below_normal(self):
        assert ratio_to_factor(5.0, 10.0, 3.0) == 0.0

    def test_ratio_to_factor_linear_ramp(self):
        # reference 10, factor 3: ramp ends at 30
        assert ratio_to_factor(20.0, 10.0, 3.0) == pytest.approx(0.5)

    def test_ratio_to_factor_caps_at_one(self):
        assert ratio_to_factor(100.0, 10.0, 3.0) == 1.0

    def test_no_baseline_is_none_never_zero(self):
        assert ratio_to_factor(100.0, None, 3.0) is None

    def test_zero_normal_positive_value_is_full_deviation(self):
        assert ratio_to_factor(4.0, 0.0, 3.0) == 1.0
        assert ratio_to_factor(0.0, 0.0, 3.0) == 0.0


# --------------------------------------------------------------------------- #
# 2. Evidence collection
# --------------------------------------------------------------------------- #


class TestEvidenceCollection:
    def test_event_mode_counts_every_category(self):
        events = [
            read_event("r1"),
            write_event("w1"),
            rewrite_event("rw1", object_key="fin-prod-archive/k"),
            delete_event("d1", object_key="fin-prod-archive/k"),
            version_delete_event("v1", object_key="fin-prod-archive/k", version_id="v1"),
            version_delete_event("v2", object_key="fin-prod-archive/k", version_id="v2"),
            snapshot_delete_event("s1", resource_id="snap-1"),
            vault_delete_event("b1", backup_vault_name="vault-a"),
            protection_event("p1"),
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        ev = collect_evidence(session, events)
        assert ev.has_event_detail
        assert ev.read_events == 1 and ev.write_events == 1
        assert ev.rewrite_events == 1 and ev.delete_events == 1
        assert ev.version_delete_events == 2
        assert ev.snapshot_delete_events == 1
        assert ev.backup_delete_events == 1
        assert ev.protection_change_events == 1
        # deletion family = delete(1) + version(2) + snapshot(1) + backup(1) = 5
        assert ev.delete_family_events == 5
        assert ev.recovery_impairing_events == 2
        assert len(ev.read_then_rewritten_keys) == 0
        assert len(ev.rewritten_then_deleted_keys) == 1

    def test_version_deletes_per_key_counts_distinct_keys(self):
        events = [
            version_delete_event(f"v{i}", object_key=f"fin-prod-archive/key{i % 2}")
            for i in range(6)
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        ev = collect_evidence(session, events)
        assert ev.version_deletes_per_key == {
            "fin-prod-archive/key0": 3,
            "fin-prod-archive/key1": 3,
        }

    def test_delete_markers_counted(self):
        events = [
            delete_event("d1", is_delete_marker=True),
            version_delete_event("v1", is_delete_marker=True),
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        ev = collect_evidence(session, events)
        assert ev.delete_marker_events == 2

    def test_protected_deletions_from_event_protection_state(self):
        events = [
            vault_delete_event("b1", backup_enabled=True, object_lock_enabled=True),
            snapshot_delete_event("s1", snapshot_protection_enabled=True),
            vault_delete_event("b2", backup_enabled=False),
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        ev = collect_evidence(session, events)
        assert ev.protected_backup_deletions == 1
        assert ev.protected_snapshot_deletions == 1

    def test_aggregate_mode_keeps_unknown_as_none(self):
        session, _ = hist_session("alice", 4, category=ActionCategory.READ)
        ev = collect_evidence(session, None)
        assert not ev.has_event_detail
        assert ev.modify_events is None
        assert ev.delete_events is None
        assert ev.delete_family_events is None
        assert ev.version_delete_events == session.version_deletions

    def test_first_destructive_index_splits_scope(self):
        events = [
            read_event("r1", resource_id="res-a", resource_arn="arn:aws:s3:::res-a"),
            delete_event("d1", resource_id="res-b", resource_arn="arn:aws:s3:::res-b"),
            delete_event("d2", resource_id="res-c", resource_arn="arn:aws:s3:::res-c"),
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        ev = collect_evidence(session, events)
        assert ev.first_destructive_index == 1
        assert ev.resources_before_first_destructive == {"arn:aws:s3:::res-a"}
        assert "arn:aws:s3:::res-c" in ev.resources_after_first_destructive


# --------------------------------------------------------------------------- #
# 3. Baselines: quality, versioning, store
# --------------------------------------------------------------------------- #


class TestBaselineBuilding:
    def test_baseline_from_trusted_history(self):
        pairs = [
            hist_session(
                "alice", 6, start=BASE_TIME + timedelta(hours=i),
                categories=[ActionCategory.READ, ActionCategory.CREATE],
            )
            for i in range(5)
        ]
        sessions = [s for s, _ in pairs]
        grouped = {s.session_id: e for s, e in pairs}
        baseline = build_baseline(sessions, events_by_session=grouped)
        assert baseline is not None
        # 5 sessions == min_sessions_for_limited(5) -> LIMITED
        assert baseline.quality == BaselineQuality.LIMITED
        assert baseline.has_evidence
        assert baseline.write_rate.mean is not None
        assert "read" in baseline.normal_operations
        assert "create" in baseline.normal_operations

    def test_baseline_quality_ladder(self):
        sessions = [hist_session("alice", 4, start=BASE_TIME + timedelta(hours=i))[0] for i in range(20)]
        baseline = build_baseline(
            sessions, cfg=BaselineConfig(min_sessions_for_good=20, min_sessions_for_limited=5)
        )
        assert baseline.quality == BaselineQuality.GOOD

    def test_baseline_versioned_and_content_stamped(self):
        sessions = [hist_session("alice", 4, start=BASE_TIME + timedelta(hours=i))[0] for i in range(6)]
        first = build_baseline(sessions, generation=1)
        second = build_baseline(sessions, generation=2)
        assert first.baseline_version != second.baseline_version
        assert first.baseline_version.startswith("gen1-")
        assert second.baseline_version.startswith("gen2-")

    def test_store_keeps_generation_history(self):
        store = BaselineStore()
        sessions = [hist_session("alice", 4, start=BASE_TIME + timedelta(hours=i))[0] for i in range(6)]
        first = store.build(sessions, actor_id="alice")
        second = store.build(sessions, actor_id="alice")
        assert store.generation == 2
        assert store.get("alice") is second
        assert store.history("alice") == [first]

    def test_insufficient_history_raises_only_on_require(self):
        session, _ = hist_session("alice", 2)
        baseline = build_baseline([session])
        assert baseline.quality == BaselineQuality.INSUFFICIENT
        with pytest.raises(Exception):
            baseline.require()

    def test_empty_history_returns_none(self):
        assert build_baseline([]) is None

    def test_novelty_fractions(self):
        history = [hist_session("alice", 4, start=BASE_TIME + timedelta(hours=i))[0] for i in range(6)]
        grouped = {s.session_id: [] for s in history}
        baseline = build_baseline(history, events_by_session=grouped)
        session, events = mass_session(n=5)
        novelty = measure_novelty(baseline, session, events)
        assert novelty.resource_novelty.available
        assert novelty.resource_novelty.value == 1.0  # all targets novel


# --------------------------------------------------------------------------- #
# 4. Baseline poisoning defense
# --------------------------------------------------------------------------- #


class TestBaselinePoisoningDefense:
    def test_benign_history_is_low(self):
        session, _ = hist_session("alice", 5, categories=[ActionCategory.READ, ActionCategory.CREATE])
        assert classify_contamination(session) == BaselineContamination.LOW

    def test_protection_change_is_medium(self):
        session, _ = hist_session("ops", 5, categories=[ActionCategory.PROTECTION_CHANGE])
        assert classify_contamination(session) == BaselineContamination.MEDIUM

    def test_bulk_version_deletes_are_excluded(self):
        """Mass version scrubbing is heavy destructive volume: HIGH (excluded)."""
        session, _ = hist_session("janitor", 25, seconds=10, category=ActionCategory.VERSION_DELETE)
        assert classify_contamination(session) == BaselineContamination.HIGH

    def test_recovery_impairing_is_high(self):
        session, _ = hist_session("cleanup", 4, seconds=60, category=ActionCategory.SNAPSHOT_DELETE)
        assert classify_contamination(session) == BaselineContamination.HIGH

    def test_mass_destruction_is_critical(self):
        session, _ = hist_session("attacker", 10, seconds=10, category=ActionCategory.BACKUP_DELETE)
        assert classify_contamination(session) == BaselineContamination.CRITICAL

    def test_mixed_history_excludes_high_and_critical(self):
        low, _ = hist_session("svc", 4, start=BASE_TIME, category=ActionCategory.READ)
        medium, _ = hist_session("svc", 5, start=BASE_TIME + timedelta(hours=2), category=ActionCategory.PROTECTION_CHANGE)
        high, _ = hist_session("svc", 4, start=BASE_TIME + timedelta(hours=4), seconds=60, category=ActionCategory.SNAPSHOT_DELETE)
        critical, _ = hist_session("svc", 10, start=BASE_TIME + timedelta(hours=6), seconds=10, category=ActionCategory.BACKUP_DELETE)
        baseline = build_baseline(
            [low, medium, high, critical],
            cfg=BaselineConfig(min_sessions_for_good=20, min_sessions_for_limited=2),
        )
        assert baseline.contamination_counts.get("critical") == 1
        assert baseline.contamination_counts.get("high") == 1
        assert baseline.learned_from_sessions == 2  # LOW + MEDIUM only
        assert baseline.excluded_sessions == 2

    def test_approval_restores_medium_but_never_high(self):
        profile = ApprovedActivityProfile(
            profile_id="lifecycle-all",
            activity="lifecycle_cleanup",
            actor_ids=frozenset({"svc"}),
        )
        medium, _ = hist_session("svc", 5, start=BASE_TIME, category=ActionCategory.PROTECTION_CHANGE)
        high, _ = hist_session("svc", 4, start=BASE_TIME + timedelta(hours=2), seconds=60, category=ActionCategory.SNAPSHOT_DELETE)
        baseline = build_baseline(
            [medium, high],
            approved_profiles=[profile],
            cfg=BaselineConfig(min_sessions_for_good=20, min_sessions_for_limited=2),
        )
        # MEDIUM session approved -> eligible with full weight;
        # HIGH stays excluded from learning entirely.
        assert baseline.learned_from_sessions == 1
        assert baseline.excluded_sessions == 1
        assert baseline.contamination_counts.get("medium") == 1
        assert baseline.contamination_counts.get("high") == 1

    def test_attacker_sessions_never_teach_baseline(self):
        attacker, _ = mass_session(n=10)
        baseline = build_baseline(
            [attacker],
            cfg=BaselineConfig(min_sessions_for_good=20, min_sessions_for_limited=2),
        )
        assert baseline is None  # fully excluded: nothing learned


# --------------------------------------------------------------------------- #
# 5. Modification analyzer
# --------------------------------------------------------------------------- #


class TestModificationAnalyzer:
    def test_zero_deviation_at_normal_volume(self):
        sessions, all_events = [], []
        for i in range(6):
            s, e = hist_session("writer", 10, start=BASE_TIME + timedelta(hours=i))
            sessions.append(s)
            all_events.append((s, e))
        grouped = {s.session_id: e for s, e in all_events}
        baseline = build_baseline(
            [s for s, _ in all_events],
            events_by_session=grouped,
            cfg=BaselineConfig(min_sessions_for_good=20, min_sessions_for_limited=5),
        )
        s2, e2 = hist_session("writer", 10, start=BASE_TIME + timedelta(hours=24))
        analysis = analyze_modification(s2, baseline, evidence=collect_evidence(s2, e2))
        assert analysis.write_rate_deviation.available
        assert analysis.write_rate_deviation.value == 0.0

    def test_high_deviation_when_write_rate_explodes(self):
        sessions, all_events = [], []
        for i in range(6):
            s, e = hist_session("writer", 10, start=BASE_TIME + timedelta(hours=i))
            sessions.append(s)
            all_events.append((s, e))
        grouped = {s.session_id: e for s, e in all_events}
        baseline = build_baseline(
            [s for s, _ in all_events],
            events_by_session=grouped,
            cfg=BaselineConfig(min_sessions_for_good=20, min_sessions_for_limited=5),
        )
        # 500 *creates* over ~41 min: far above 3x the normal write pace
        burst, burst_events = hist_session(
            "writer", 500, seconds=5, start=BASE_TIME + timedelta(hours=24),
            category=ActionCategory.CREATE,
        )
        analysis = analyze_modification(burst, baseline, evidence=collect_evidence(burst, burst_events))
        assert analysis.write_rate_deviation.value == 1.0

    def test_no_baseline_is_unavailable_never_zero(self):
        session, events = hist_session("ghost", 5)
        analysis = analyze_modification(session, None, evidence=collect_evidence(session, events))
        assert analysis.write_rate_deviation.available is False
        assert analysis.write_rate_deviation.value is None
        assert analysis.write_rate_deviation.reason == "no_baseline"

    def test_missing_write_detail_is_event_detail_missing(self):
        session, _ = hist_session("agg", 5, category=ActionCategory.READ)
        analysis = analyze_modification(session, None, evidence=collect_evidence(session, None))
        assert analysis.write_rate_deviation.reason == "event_detail_missing"


# --------------------------------------------------------------------------- #
# 6. Deletion analyzer
# --------------------------------------------------------------------------- #


class TestDeletionAnalyzer:
    def test_mass_deletion_features(self):
        # 50 deletes over ~4 min: pace 750/h towers over the 120/h cap
        session, events = mass_session(n=50)
        result = analyze_deletion(session, None, evidence=collect_evidence(session, events))
        assert result.delete_count == 50
        assert result.unique_deleted_resources == 50
        assert result.delete_rate_deviation.reason == "no_baseline"
        raw = result.delete_rate_deviation.raw
        assert raw["delete_family_events"] == 50
        assert result.delete_rate_deviation.raw["delete_family_events"] == 50

    def test_baseline_relative_deviation(self):
        history, grouped = [], {}
        for i in range(6):
            s, e = hist_session(
                "janitor", 10, start=BASE_TIME + timedelta(hours=i),
                categories=[ActionCategory.READ, ActionCategory.DELETE],
            )
            history.append(s)
            grouped[s.session_id] = e
        baseline = build_baseline(
            history,
            events_by_session=grouped,
            cfg=BaselineConfig(min_sessions_for_good=20, min_sessions_for_limited=5),
        )
        # a day exactly like history: 10 events / 270 s, half deletes
        normal, normal_events = hist_session(
            "janitor", 10, start=BASE_TIME + timedelta(hours=24),
            categories=[ActionCategory.READ, ActionCategory.DELETE],
        )
        result = analyze_deletion(normal, baseline, evidence=collect_evidence(normal, normal_events))
        assert result.delete_rate_deviation.value == 0.0
        # 50 deletions across 50 resources -> full deviation
        burst, burst_events = mass_session(n=50, actor="janitor")
        result = analyze_deletion(burst, baseline, evidence=collect_evidence(burst, burst_events))
        assert result.delete_rate_deviation.value == 1.0

    def test_aggregate_mode_uses_documented_lower_bound(self):
        session, _ = mass_session(n=4)
        result = analyze_deletion(session, None, evidence=collect_evidence(session, None))
        assert result.delete_count == 4  # destructive - rewrite - protection


# --------------------------------------------------------------------------- #
# 7. Versioning analyzer
# --------------------------------------------------------------------------- #


class TestVersioningAnalyzer:
    def test_version_burst_without_baseline_uses_absolute_pace(self):
        events = [
            version_delete_event(
                f"v{i}",
                timestamp=BASE_TIME + timedelta(seconds=30 * i),
                object_key=f"fin-prod-archive/key{i % 5}",
            )
            for i in range(20)
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_versioning(session, None, evidence=collect_evidence(session, events))
        assert result.version_delete_anomaly.available
        assert result.version_delete_anomaly.value == 1.0  # 20 versions in <10 min
        assert result.version_delete_anomaly.raw["unique_keys_targeted"] == 5

    def test_version_deletion_ratio_is_distinct_signal(self):
        # 20 version deletes + 5 plain deletes: ratio 0.8; spread over 10 min
        events = [
            version_delete_event(f"v{i}", timestamp=BASE_TIME + timedelta(seconds=30 * i))
            for i in range(20)
        ]
        events += [
            delete_event(f"d{i}", timestamp=BASE_TIME + timedelta(seconds=600 + 30 * i))
            for i in range(5)
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_versioning(session, None, evidence=collect_evidence(session, events))
        ratio = result.version_deletion_ratio
        assert ratio.available and ratio.value == pytest.approx(0.8)

    def test_plain_delete_only_has_no_version_signal(self):
        events = [delete_event(f"d{i}", timestamp=BASE_TIME + timedelta(seconds=30 * i)) for i in range(5)]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_versioning(session, None, evidence=collect_evidence(session, events))
        assert result.version_deletion_ratio.value == 0.0


# --------------------------------------------------------------------------- #
# 8. Snapshot + backup analyzers
# --------------------------------------------------------------------------- #


class TestSnapshotBackupAnalyzers:
    def test_snapshot_delete_score_volume_pace(self):
        # 5 snapshot deletes spread over 8 min: volume term 5/cap10=0.5
        # dominates the pace term (37.5/h vs 120/h cap)
        events = [
            snapshot_delete_event(f"s{i}", timestamp=BASE_TIME + timedelta(seconds=120 * i))
            for i in range(5)
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_snapshots(session, None, evidence=collect_evidence(session, events))
        assert result.snapshot_delete_score.value == pytest.approx(0.5)
        assert result.snapshot_scope_anomaly.reason == "no_baseline"

    def test_snapshot_criticality_recorded_in_raw(self):
        events = [
            snapshot_delete_event(
                "s1", business_criticality=BusinessCriticality.CRITICAL
            )
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_snapshots(session, None, evidence=collect_evidence(session, events))
        assert result.snapshot_delete_score.raw["critical_resource_touched"] is True

    def test_backup_delete_score_vault_and_recovery_points(self):
        # 4 vault deletes spread over 7.5 min: volume 4/cap10=0.4 dominates
        events = [vault_delete_event(f"v{i}", timestamp=BASE_TIME + timedelta(seconds=150 * i)) for i in range(4)]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_backup(session, None, evidence=collect_evidence(session, events))
        assert result.backup_delete_score.value == pytest.approx(0.4)
        assert result.recovery_point_anomaly.reason == "no_recovery_point_activity"

    def test_recovery_point_breadth(self):
        events = [
            make_event(
                event_id=f"rp{i}",
                timestamp=BASE_TIME + timedelta(minutes=i),
                action_category=ActionCategory.RECOVERY_POINT_DELETE,
                raw_action="backup:DeleteRecoveryPoint",
                resource_id=f"rp-{i}",
            )
            for i in range(3)
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_backup(session, None, evidence=collect_evidence(session, events))
        assert result.recovery_point_anomaly.available
        assert result.recovery_point_anomaly.raw["unique_recovery_points"] == 3

    def test_zero_deletions_are_explicit_zero(self):
        session, events = hist_session("alice", 3)
        snap = analyze_snapshots(session, None, evidence=collect_evidence(session, events))
        bak = analyze_backup(session, None, evidence=collect_evidence(session, events))
        assert snap.snapshot_delete_score.value == 0.0
        assert bak.backup_delete_score.value == 0.0


# --------------------------------------------------------------------------- #
# 9. Recovery destruction / protection degradation / recoverability
# --------------------------------------------------------------------------- #


class TestRecoveryProtectionRecoverability:
    def test_recovery_destruction_volume_and_pace(self):
        # same pacing as the backup test: volume term dominates at 0.4
        events = [vault_delete_event(f"v{i}", timestamp=BASE_TIME + timedelta(seconds=150 * i)) for i in range(4)]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_recoverability(session, None, evidence=collect_evidence(session, events))
        assert result.recovery_destruction_score.value == pytest.approx(0.4)
        assert result.recovery_destruction_score.raw["backup_deletions"] == 4

    def test_protection_degradation_independent_from_data_destruction(self):
        # only deletes: protection degradation must stay 0.0
        events = [delete_event(f"d{i}", timestamp=BASE_TIME) for i in range(20)]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_recoverability(session, None, evidence=collect_evidence(session, events))
        assert result.protection_degradation_score.value == 0.0
        assert result.protection_degradation_score.raw["protection_changes"] == 0

        # only protection changes: recovery destruction must stay 0.0
        events = [protection_event(f"p{i}", timestamp=BASE_TIME) for i in range(2)]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_recoverability(session, None, evidence=collect_evidence(session, events))
        assert result.recovery_destruction_score.value == 0.0
        assert result.protection_degradation_score.value > 0.0

    def test_recoverability_full_when_no_recovery_state_touched(self):
        session, events = hist_session("alice", 5)
        result = analyze_recoverability(session, None, evidence=collect_evidence(session, events))
        assert result.recoverability_score.value == 1.0

    def test_recoverability_honors_protected_deletions(self):
        events = [
            vault_delete_event("v1", backup_enabled=True, object_lock_enabled=True)
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_recoverability(session, None, evidence=collect_evidence(session, events))
        assert result.recoverability_score.value == 1.0  # protected copy destroyed but lock remains

    def test_recoverability_drops_with_unprotected_deletions(self):
        events = [vault_delete_event("v1", backup_enabled=False)]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_recoverability(session, None, evidence=collect_evidence(session, events))
        assert result.recoverability_score.value == pytest.approx(0.0)


# --------------------------------------------------------------------------- #
# 10. Rewrite/transform analyzer
# --------------------------------------------------------------------------- #


class TestRewriteAnalyzer:
    def test_no_rewrites_is_zero(self):
        session, events = hist_session("alice", 5)
        result = analyze_rewrite(session, None, evidence=collect_evidence(session, events))
        assert result.rewrite_transform_score.value == 0.0

    def test_read_rewrite_delete_original_chain(self):
        events = [
            read_event("r1", object_key="k1", timestamp=BASE_TIME),
            rewrite_event("rw1", object_key="k1", timestamp=BASE_TIME + timedelta(seconds=10)),
            delete_event("d1", object_key="k1", timestamp=BASE_TIME + timedelta(seconds=20)),
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_rewrite(session, None, evidence=collect_evidence(session, events))
        assert result.rewrite_transform_score.value > 0.0
        assert result.rewrite_transform_score.raw["rewrite_then_delete_original_keys"] == 1
        assert "read_rewrite_replace_delete_original" in result.transform_chains

    def test_naming_discipline_content_neutral(self):
        """The feature must never claim encryption — it is transform evidence."""
        events = [
            rewrite_event(f"rw{i}", object_key=f"k{i}", timestamp=BASE_TIME)
            for i in range(10)
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_rewrite(session, None, evidence=collect_evidence(session, events))
        dumped = result.rewrite_transform_score.model_dump()
        assert "not an encryption verdict" in dumped["raw"]["note"]
        # and the vector-level field name stays transform-flavored
        assert "ransomware" not in SessionFeatureVector.model_fields


# --------------------------------------------------------------------------- #
# 11. Temporal analyzer
# --------------------------------------------------------------------------- #


class TestTemporalAnalyzer:
    def test_destructive_burst_detected(self):
        session, events = mass_session(n=50, seconds=5)
        result = analyze_temporal(session, None, evidence=collect_evidence(session, events))
        assert result.burst_detected is True
        assert result.slow_destruction_detected is False
        assert result.temporal_anomaly.value >= 0.35

    def test_calm_activity_has_zero_temporal_anomaly(self):
        session, events = hist_session("alice", 6, seconds=1800)  # 2.5 h
        result = analyze_temporal(session, None, evidence=collect_evidence(session, events))
        assert result.burst_detected is False
        assert result.scope_expansion_detected is False
        assert result.temporal_anomaly.value == 0.0

    def test_window_census_reported(self):
        session, events = mass_session(n=20, seconds=10)
        result = analyze_temporal(session, None, evidence=collect_evidence(session, events))
        census = result.temporal_anomaly.raw["window_census_max_events"]
        for window in ("60", "300", "900", "3600", "21600", "86400"):
            assert f"{window}s" in census
        assert census["300s"] == 20


# --------------------------------------------------------------------------- #
# 12. Sequence analyzer
# --------------------------------------------------------------------------- #


class TestSequenceAnalyzer:
    def test_protection_change_before_destruction(self):
        events = [
            protection_event("p1", timestamp=BASE_TIME),
            delete_event("d1", timestamp=BASE_TIME + timedelta(seconds=30)),
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        result = analyze_sequences(session, None, evidence=collect_evidence(session, events))
        assert result.protection_before_destruction is True
        assert result.sequence_anomaly.value >= 0.4

    def test_needs_event_detail(self):
        session, _ = mass_session(n=3)
        result = analyze_sequences(session, None, evidence=collect_evidence(session, None))
        assert result.sequence_anomaly.reason == "event_detail_missing"


# --------------------------------------------------------------------------- #
# 13. Approved-activity context
# --------------------------------------------------------------------------- #


class TestApprovedActivityContext:
    def _profile(self, **overrides) -> ApprovedActivityProfile:
        defaults = dict(
            profile_id="lifecycle-nightly",
            activity="lifecycle_cleanup",
            version="3",
            justification="ticket-1234 approved nightly cleanup",
            actor_ids=frozenset({"cleanup-bot"}),
        )
        defaults.update(overrides)
        return ApprovedActivityProfile(**defaults)

    def test_matching_profile_approves(self):
        session, events = hist_session("cleanup-bot", 10, category=ActionCategory.DELETE)
        context = match_profile(session, [self._profile()], events)
        assert context is not None
        assert context.approved and context.profile_id == "lifecycle-nightly"
        assert "actor" in context.matched_constraints

    def test_scoping_by_operation(self):
        profile = self._profile(operations=frozenset({ActionCategory.READ.value}))
        session, events = hist_session("cleanup-bot", 4, category=ActionCategory.DELETE)
        assert match_profile(session, [profile], events) is None

    def test_scoping_by_resource(self):
        # resources_touched carries ARN-or-id strings; scope on the exact ARN
        arn = "arn:aws:s3:::fin-prod-archive/reports/x.json"
        profile = self._profile(resource_ids=frozenset({arn}))
        session, events = hist_session("cleanup-bot", 4, category=ActionCategory.DELETE)
        assert match_profile(session, [profile], events) is not None
        other, other_events = hist_session("cleanup-bot", 4, category=ActionCategory.DELETE)
        profile2 = self._profile(resource_ids=frozenset({"arn:aws:s3:::other-bucket/x"}))
        assert match_profile(other, [profile2], other_events) is None

    def test_time_aware_window(self):
        profile = self._profile(hours_start=2, hours_end=4)
        session, events = hist_session("cleanup-bot", 4, start=BASE_TIME.replace(hour=3))
        assert match_profile(session, [profile], events) is not None
        session, events = hist_session("cleanup-bot", 4, start=BASE_TIME.replace(hour=12))
        assert match_profile(session, [profile], events) is None

    def test_time_window_wraps_midnight(self):
        profile = self._profile(hours_start=22, hours_end=4)
        session, events = hist_session("cleanup-bot", 4, start=BASE_TIME.replace(hour=23))
        assert match_profile(session, [profile], events) is not None

    def test_expired_profile_not_approved(self):
        profile = self._profile(valid_until=BASE_TIME - timedelta(days=1))
        session, events = hist_session("cleanup-bot", 4, category=ActionCategory.DELETE)
        assert match_profile(session, [profile], events) is None

    def test_reversible_by_disable(self):
        profile = self._profile(enabled=False)
        session, events = hist_session("cleanup-bot", 4, category=ActionCategory.DELETE)
        assert match_profile(session, [profile], events) is None
        revived = ApprovedActivityProfile(
            profile_id=profile.profile_id,
            activity=profile.activity,
            version=profile.version,
            justification=profile.justification,
            actor_ids=profile.actor_ids,
            enabled=True,
        )
        assert match_profile(session, [revived], events) is not None

    def test_approval_is_auditable(self):
        session, events = hist_session("cleanup-bot", 4, category=ActionCategory.DELETE)
        context = match_profile(session, [self._profile()], events)
        assert context.justification == "ticket-1234 approved nightly cleanup"
        assert context.profile_version == "3"


# --------------------------------------------------------------------------- #
# 14. extract_features integration
# --------------------------------------------------------------------------- #


class TestExtractFeaturesIntegration:
    def test_calm_session_features_are_low(self):
        sessions, events = [], []
        for i in range(3):
            s, e = hist_session("app-tier", 10, start=BASE_TIME + timedelta(hours=i))
            sessions.append(s)
            events.extend(e)
        vectors = extract_features(sessions, events)
        assert len(vectors) == 3
        vector = vectors[0]
        assert vector.temporal is not None and vector.temporal.value == 0.0
        assert vector.delete_count == 0

    def test_mass_deletion_session_features(self):
        sessions, events = [], []
        for i in range(6):
            s, e = hist_session("app-tier", 8, start=BASE_TIME + timedelta(hours=i))
            sessions.append(s)
            events.extend(e)
        burst, burst_events = mass_session(n=50, actor="app-tier", start=BASE_TIME + timedelta(hours=10))
        vectors = extract_features(sessions + [burst], events + burst_events)
        mass_vector = vectors[-1]
        assert mass_vector.delete_count == 50
        assert mass_vector.unique_deleted_resources == 50
        assert mass_vector.temporal.value >= 0.35
        # leave-one-out: the burst session's baseline came from the 6 calm ones
        assert mass_vector.baseline_quality == BaselineQuality.LIMITED

    def test_version_deletion_features(self):
        events = [
            version_delete_event(
                f"v{i}",
                timestamp=BASE_TIME + timedelta(seconds=30 * i),
                object_key=f"fin-prod-archive/key{i % 5}",
            )
            for i in range(20)
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        vector = extract_features([session], events)[0]
        assert vector.version_delete_count == 20
        assert vector.unique_versions_deleted == 5
        assert vector.version_deletion_rate_per_hour > 0
        assert vector.version_delete_anomaly.value == 1.0

    def test_snapshot_and_recovery_features(self):
        snap_events = [
            snapshot_delete_event(f"s{i}", timestamp=BASE_TIME + timedelta(seconds=30 * i))
            for i in range(5)
        ]
        snap_session = DestructiveSessionBuilder().build_sessions(snap_events)[0]
        rp_events = [
            make_event(
                event_id=f"rp{i}",
                timestamp=BASE_TIME + timedelta(minutes=i),
                action_category=ActionCategory.RECOVERY_POINT_DELETE,
                raw_action="backup:DeleteRecoveryPoint",
                resource_id=f"rp-{i}",
            )
            for i in range(3)
        ]
        rp_session = DestructiveSessionBuilder().build_sessions(rp_events)[0]
        vectors = extract_features(
            [snap_session, rp_session], snap_events + rp_events
        )
        assert vectors[0].ebs_snapshot_deletions == 5
        assert vectors[0].snapshot_delete_anomaly is not None
        assert vectors[1].unique_recovery_points_deleted == 3
        assert vectors[1].recovery_destruction.available

    def test_baseline_poisoning_visible_on_vector(self):
        attacker, events = mass_session(n=12)
        vector = extract_features([attacker], events)[0]
        # single mass-destruction session -> its own baseline is leave-one-out empty
        assert vector.baseline_quality == BaselineQuality.NONE
        # 12 plain-object deletions: heavy destructive volume -> HIGH (excluded;
        # CRITICAL is reserved for recovery-impairing volume, e.g. backups)
        assert classify_contamination(attacker) == BaselineContamination.HIGH

    def test_approved_activity_integrated(self):
        profile = ApprovedActivityProfile(
            profile_id="lifecycle-nightly",
            activity="lifecycle_cleanup",
            actor_ids=frozenset({"cleanup-bot"}),
        )
        session, events = hist_session("cleanup-bot", 10, category=ActionCategory.DELETE)
        vector = extract_features([session], events, approved_profiles=[profile])[0]
        assert vector.approved_activity.approved is True
        assert vector.approved_activity.profile_id == "lifecycle-nightly"

    def test_business_criticality_from_events(self):
        events = [
            delete_event(
                "d1",
                business_criticality=BusinessCriticality.CRITICAL,
                timestamp=BASE_TIME,
            )
        ]
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        vector = extract_features([session], events)[0]
        assert vector.business_criticality == BusinessCriticality.CRITICAL

    def test_baseline_store_not_contaminated_by_extract(self):
        store = BaselineStore()
        session, events = hist_session("alice", 5)
        extract_features([session], events, baseline_store=store)
        assert store.get("alice") is None  # leave-one-out never persists
        assert store.generation == 0

    def test_data_provenance_attached(self):
        session, events = hist_session("alice", 3)
        provenance = DataProvenance(source_type="synthetic", ingestion_pipeline="test")
        vector = extract_features([session], events, data_provenance=provenance)[0]
        assert vector.data_provenance is provenance

    def test_vectors_serializable(self):
        session, events = mass_session(n=5)
        vector = extract_features([session], events)[0]
        assert len(vector.model_dump_json()) > 100


# --------------------------------------------------------------------------- #
# 15. No-verdict invariants
# --------------------------------------------------------------------------- #


class TestNoVerdictFields:
    def test_feature_vector_has_no_destruction_score(self):
        dumped = SessionFeatureVector(session_id="s").model_dump()
        for forbidden in ("destruction_score", "severity", "verdict", "is_ransomware"):
            assert forbidden not in dumped, forbidden
        for key in dumped:
            assert "severity" not in key and "verdict" not in key

    def test_feature_vector_fields_are_evidence_shaped(self):
        fields = set(SessionFeatureVector.model_fields)
        expected = {
            "write_rate_deviation",
            "modify_rate_deviation",
            "rewrite_rate_deviation",
            "resource_scope_deviation",
            "object_count_deviation",
            "delete_rate_deviation",
            "delete_ratio_anomaly",
            "deletion_scope_anomaly",
            "version_delete_anomaly",
            "version_deletion_ratio",
            "snapshot_delete_anomaly",
            "snapshot_scope_anomaly",
            "backup_delete_anomaly",
            "backup_anomaly",
            "recovery_point_anomaly",
            "recovery_destruction",
            "protection_degradation",
            "recoverability",
            "rewrite_transform",
            "sequence_anomaly",
            "actor_resource_novelty",
            "actor_operation_novelty",
            "actor_scope_novelty",
            "temporal",
            "business_criticality",
            "approved_activity",
            "baseline_quality",
            "feature_availability",
            "feature_provenance",
        }
        missing = expected - fields
        assert missing == set()
