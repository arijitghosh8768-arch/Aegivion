"""Deterministic feature extraction for destructive sessions — **Part 2**.

Produces a documented, fully-explained :class:`SessionFeatureVector` per
:class:`~detection.cloud_destruction.schemas.DestructiveActivitySession`,
fusing the Part 2 behavioral analyzers (modification, deletion, versioning,
snapshot, backup, recovery, protection, rewrite, sequence, temporal) with
baseline deviation, actor novelty, legitimate-activity context and
baseline-quality reporting.

Rules carried over from Part 1:

1. **No ML** — every value below is deterministic and explainable. The
   unsupervised anomaly layer (:mod:`detection.cloud_destruction.anomaly`)
   is still a Part 3 placeholder, as are scoring, confidence and findings.
2. **No verdicts.** A feature vector is evidence, not a verdict: there is
   no ``destruction_score``, no ``severity``, no ``is_ransomware`` here.
3. **Never invent values.** A feature the evidence cannot support is a
   :class:`~detection.cloud_destruction.provenance.MeasuredValue` with
   ``available=False`` and a machine-readable reason — never zero.
4. **Deviation semantics.** All ``*_deviation`` / ``*_anomaly`` values are
   normalized to ``[0, 1]``: 0.0 at/below normal, 1.0 at/above the
   configured factor over normal, linear in between.
5. **Raw counts ride along** on every derived value so any downstream
   score can be audited back to raw telemetry.
6. **Baseline hygiene is explicit**: leave-one-session-out history for the
   session under analysis, plus per-vector ``baseline_quality``,
   ``baseline_version`` and poisoning-exclusion counts.
"""

from __future__ import annotations

from typing import Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from detection.cloud_destruction.backup import analyze_backup
from detection.cloud_destruction.baseline import (
    BaselineQuality,
    BaselineStore,
    measure_novelty,
)
from detection.cloud_destruction.config import DestructionDetectorConfig
from detection.cloud_destruction.deletion import analyze_deletion
from detection.cloud_destruction.deviation import hour_span
from detection.cloud_destruction.evidence import collect_evidence
from detection.cloud_destruction.legitimate import ActivityContext, ApprovedActivityProfile, match_profile
from detection.cloud_destruction.modification import analyze_modification
from detection.cloud_destruction.provenance import (
    DataProvenance,
    FeatureProvenance,
    MeasuredValue,
)
from detection.cloud_destruction.protection import analyze_protection_changes
from detection.cloud_destruction.recoverability import analyze_recoverability
from detection.cloud_destruction.rewrite import analyze_rewrite
from detection.cloud_destruction.schemas import (
    BusinessCriticality,
    DestructiveActivitySession,
    ResourceActivityEvent,
)
from detection.cloud_destruction.sequence import analyze_sequences
from detection.cloud_destruction.snapshot import analyze_snapshots
from detection.cloud_destruction.temporal import analyze_temporal
from detection.cloud_destruction.versioning import analyze_versioning

__all__ = [
    "MeasuredValue",
    "SessionFeatureVector",
    "extract_features",
]


class SessionFeatureVector(BaseModel):
    """Full behavioral feature vector for one destructive session.

    Grouped per the Part 2 deliverables. Every derived feature is a
    :class:`MeasuredValue` so absence of evidence is always explicit;
    raw Part 1 counters (delete counts, rates, version/snapshot/backup
    volumes) are kept alongside for audit and Part 3 fusion.
    """

    model_config = ConfigDict(extra="forbid")

    session_id: str
    actor_id: Optional[str] = None

    # -- modification intelligence -------------------------------------------
    write_rate_deviation: Optional[MeasuredValue] = None
    modify_rate_deviation: Optional[MeasuredValue] = None
    rewrite_rate_deviation: Optional[MeasuredValue] = None
    resource_scope_deviation: Optional[MeasuredValue] = None
    object_count_deviation: Optional[MeasuredValue] = None

    # -- deletion intelligence -------------------------------------------------
    delete_rate_deviation: Optional[MeasuredValue] = None
    delete_ratio_anomaly: Optional[MeasuredValue] = None
    deletion_scope_anomaly: Optional[MeasuredValue] = None
    delete_count: int = 0
    delete_rate_per_hour: Optional[float] = None
    delete_ratio: Optional[float] = None
    """Deletion-family share of all events (raw evidence, not a deviation)."""
    unique_deleted_resources: int = 0

    # -- version destruction ------------------------------------------------------
    version_delete_anomaly: Optional[MeasuredValue] = None
    version_deletion_ratio: Optional[MeasuredValue] = None
    version_delete_count: int = 0
    delete_marker_count: int = 0
    version_deletion_rate_per_hour: Optional[float] = None
    unique_versions_deleted: Optional[int] = None

    # -- snapshot analysis ----------------------------------------------------------
    snapshot_delete_anomaly: Optional[MeasuredValue] = None
    snapshot_scope_anomaly: Optional[MeasuredValue] = None
    ebs_snapshot_deletions: int = 0
    rds_snapshot_deletions: int = 0
    unique_snapshots_deleted: Optional[int] = None

    # -- backup / recovery analysis ----------------------------------------------------
    backup_delete_anomaly: Optional[MeasuredValue] = None
    backup_anomaly: Optional[MeasuredValue] = None
    recovery_point_anomaly: Optional[MeasuredValue] = None
    unique_recovery_points_deleted: Optional[int] = None

    # -- protection degradation + recoverability -------------------------------------------
    recovery_destruction: Optional[MeasuredValue] = None
    protection_degradation: Optional[MeasuredValue] = None
    recoverability: Optional[MeasuredValue] = None

    # -- mass rewrite / transform -----------------------------------------------------------
    rewrite_transform: Optional[MeasuredValue] = None

    # -- ordering + actor novelty + temporal ----------------------------------------------------
    sequence_anomaly: Optional[MeasuredValue] = None
    actor_resource_novelty: Optional[MeasuredValue] = None
    actor_operation_novelty: Optional[MeasuredValue] = None
    actor_scope_novelty: Optional[MeasuredValue] = None
    temporal: Optional[MeasuredValue] = None

    # -- context ------------------------------------------------------------------------------
    business_criticality: Optional[BusinessCriticality] = None
    approved_activity: ActivityContext = Field(default_factory=ActivityContext)

    # -- baseline hygiene -------------------------------------------------------------------------
    baseline_quality: BaselineQuality = BaselineQuality.NONE
    baseline_version: Optional[str] = None
    baseline_excluded_sessions: Optional[int] = None
    baseline_contamination: dict[str, int] = Field(default_factory=dict)

    # -- self-description ------------------------------------------------------------------------------
    feature_availability: tuple[str, ...] = Field(default_factory=tuple)
    """Names of features carrying an explicit availability record."""
    feature_provenance: dict[str, FeatureProvenance] = Field(default_factory=dict)
    data_provenance: Optional[DataProvenance] = None

    _FEATURE_NAMES = (
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
    )

    @property
    def recovery_destruction_score(self) -> Optional[MeasuredValue]:
        """Spec name for :attr:`recovery_destruction`."""
        return self.recovery_destruction

    @property
    def protection_degradation_score(self) -> Optional[MeasuredValue]:
        """Spec name for :attr:`protection_degradation`."""
        return self.protection_degradation

    @property
    def rewrite_transform_score(self) -> Optional[MeasuredValue]:
        """Spec name for :attr:`rewrite_transform`."""
        return self.rewrite_transform

    @property
    def available_features(self) -> tuple[str, ...]:
        return tuple(
            name
            for name in self._FEATURE_NAMES
            if (value := getattr(self, name)) is not None and value.available
        )


def extract_features(
    sessions: Sequence[DestructiveActivitySession],
    events: Optional[Sequence[ResourceActivityEvent]] = None,
    *,
    baseline_store: Optional[BaselineStore] = None,
    approved_profiles: Optional[Sequence[ApprovedActivityProfile]] = None,
    config: Optional[DestructionDetectorConfig] = None,
    data_provenance: Optional[DataProvenance] = None,
) -> list[SessionFeatureVector]:
    """Extract the deterministic behavioral feature vector for each session.

    ``events`` optionally supplies the canonical events behind each session
    (matched via ``event.session_id``); with detail, every analyzer runs in
    event mode, without it the Part 1 session aggregates are used and
    detail-dependent features report honest unavailability.

    Baselines are built per actor from the *other* sessions
    (leave-one-out), so a session never teaches its own baseline. Pure and
    side-effect free; no ML, no verdicts.
    """
    cfg = config or DestructionDetectorConfig()
    bcfg = cfg.behavioral
    store = baseline_store if baseline_store is not None else BaselineStore(
        approved_profiles=approved_profiles
    )

    # Events are matched to sessions by event_id membership (Part 1 sessions
    # carry ``event_ids``); ``event.session_id`` is honored as a fallback.
    event_by_id: dict[str, ResourceActivityEvent] = {}
    for event in events or []:
        event_by_id[event.event_id] = event

    per_session: dict[str, list[ResourceActivityEvent]] = {}
    for sess in sessions:
        matched = [event_by_id[eid] for eid in sess.event_ids if eid in event_by_id]
        if not matched:
            matched = [e for e in (events or []) if e.session_id == sess.session_id]
        per_session[sess.session_id] = matched

    vectors: list[SessionFeatureVector] = []
    for index, session in enumerate(sessions):
        others = [s for i, s in enumerate(sessions) if i != index]
        session_events = per_session.get(session.session_id, [])
        history_map = {
            sid: evts for sid, evts in per_session.items() if sid != session.session_id
        }

        baseline = store.get_or_build(
            session.actor_id,
            others,
            cfg=cfg.baseline,
            events_by_session=history_map or None,
        )
        novelty = measure_novelty(baseline, session, session_events)
        ev = collect_evidence(session, session_events or None)

        mod = analyze_modification(session, baseline, config=bcfg, evidence=ev)
        dele = analyze_deletion(session, baseline, config=bcfg, evidence=ev)
        vers = analyze_versioning(session, baseline, config=bcfg, evidence=ev)
        snap = analyze_snapshots(session, baseline, config=bcfg, evidence=ev)
        back = analyze_backup(session, baseline, config=bcfg, evidence=ev)
        rec = analyze_recoverability(session, baseline, config=bcfg, evidence=ev)
        rew = analyze_rewrite(session, baseline, config=bcfg, evidence=ev)
        seq = analyze_sequences(session, baseline, config=bcfg, evidence=ev)
        tmp = analyze_temporal(session, baseline, config=bcfg, evidence=ev)
        protection = analyze_protection_changes(session, session_events)

        hours = hour_span(ev.event_count, ev.duration_seconds, bcfg.min_session_seconds)
        approved = match_profile(session, approved_profiles or [], session_events)

        criticality = (
            BusinessCriticality.CRITICAL
            if session.critical_resource_touched
            else ev.max_criticality
        )

        vector = SessionFeatureVector(
            session_id=session.session_id,
            actor_id=session.actor_id,
            write_rate_deviation=mod.write_rate_deviation,
            modify_rate_deviation=mod.modify_rate_deviation,
            rewrite_rate_deviation=mod.rewrite_rate_deviation,
            resource_scope_deviation=mod.resource_scope_deviation,
            object_count_deviation=mod.object_count_deviation,
            delete_rate_deviation=dele.delete_rate_deviation,
            delete_ratio_anomaly=dele.delete_ratio_anomaly,
            deletion_scope_anomaly=dele.deletion_scope_anomaly,
            delete_count=dele.delete_count,
            delete_rate_per_hour=dele.delete_rate_per_hour,
            delete_ratio=ev.delete_ratio,
            unique_deleted_resources=dele.unique_deleted_resources,
            version_delete_anomaly=vers.version_delete_anomaly,
            version_deletion_ratio=vers.version_deletion_ratio,
            version_delete_count=ev.version_delete_events or 0,
            delete_marker_count=ev.delete_marker_events or 0,
            version_deletion_rate_per_hour=(ev.version_delete_events or 0) / hours,
            unique_versions_deleted=(
                len(ev.version_deletes_per_key) if ev.version_deletes_per_key else None
            ),
            snapshot_delete_anomaly=snap.snapshot_delete_score,
            snapshot_scope_anomaly=snap.snapshot_scope_anomaly,
            ebs_snapshot_deletions=ev.ebs_snapshot_delete_events or 0,
            rds_snapshot_deletions=ev.rds_snapshot_delete_events or 0,
            unique_snapshots_deleted=ev.unique_snapshots,
            backup_delete_anomaly=back.backup_delete_score,
            backup_anomaly=back.backup_anomaly,
            recovery_point_anomaly=back.recovery_point_anomaly,
            unique_recovery_points_deleted=ev.unique_recovery_points,
            recovery_destruction=rec.recovery_destruction_score,
            protection_degradation=protection.protection_degradation_score,
            recoverability=rec.recoverability_score,
            rewrite_transform=rew.rewrite_transform_score,
            sequence_anomaly=seq.sequence_anomaly,
            actor_resource_novelty=novelty.resource_novelty,
            actor_operation_novelty=novelty.operation_novelty,
            actor_scope_novelty=novelty.scope_novelty,
            temporal=tmp.temporal_anomaly,
            business_criticality=criticality,
            approved_activity=approved or ActivityContext(),
            baseline_quality=baseline.quality if baseline else BaselineQuality.NONE,
            baseline_version=baseline.baseline_version if baseline else None,
            baseline_excluded_sessions=baseline.excluded_sessions if baseline else None,
            baseline_contamination=dict(baseline.contamination_counts) if baseline else {},
            data_provenance=data_provenance,
        )

        provenance: dict[str, FeatureProvenance] = {}
        for name in vector._FEATURE_NAMES:
            value = getattr(vector, name)
            if value is None:
                continue
            provenance[name] = FeatureProvenance(
                method=value.method,
                contributors=value.contributors,
                confidence=value.confidence,
                baseline_quality=baseline.quality.value if baseline else None,
                baseline_version=baseline.baseline_version if baseline else None,
            )
        vector.feature_provenance = provenance
        vector.feature_availability = tuple(
            name
            for name in vector._FEATURE_NAMES
            if (value := getattr(vector, name)) is not None
        )
        vectors.append(vector)
    return vectors
