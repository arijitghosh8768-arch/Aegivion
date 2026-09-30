"""BehavioralProfiler: assembles the BehavioralFeatureSet for each session.

Wires the eight intelligence dimensions together against the baseline
engine, known universes, and registries. It produces structured features
ONLY — the final risk verdict is Part 3 (risk fusion).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.config import DetectorConfig
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession

from .access_pattern_intelligence import (
    KnownAccessUniverse,
    access_pattern_score,
    access_pattern_signals,
)
from .actor_resource_intelligence import (
    ActorResourceHistory,
    actor_resource_signals,
)
from .baseline_engine import BaselineEngine
from .baseline_guard import BaselineInfluence
from .destination_intelligence import DestinationAssessment, KnownUniverse, assess_destinations
from .egress_intelligence import egress_signals
from .feature_set import AvailableFeature, BehavioralFeatureSet, FeatureAvailability
from .sequence import SequenceResult, score_sequence, session_action_sequence
from .sensitivity_intelligence import sensitivity_signals
from .time_intelligence import ApprovedSchedule, record_time_history, time_anomaly
from .volume_intelligence import VolumeDeviations, volume_deviations


@dataclass
class IntelligenceContext:
    """Everything the profiler may need; all optional, all honest."""

    known_destinations: KnownUniverse | None = None
    known_access: KnownAccessUniverse | None = None
    actor_resource_history: ActorResourceHistory | None = None
    resource_business_units: dict[str, str] | None = None
    actor_business_unit: str | None = None
    resource_sensitivity: dict[str, tuple] | None = None
    resource_criticality: dict[str, float] | None = None
    schedules: Sequence[ApprovedSchedule] = field(default_factory=tuple)
    peer_group: str | None = None
    workload_id: str | None = None


@dataclass
class BehavioralProfileResult:
    """Feature set plus the per-dimension assessment objects."""

    features: BehavioralFeatureSet
    volume: VolumeDeviations
    destinations: DestinationAssessment
    sequence: SequenceResult
    time: Any
    egress: Any
    access_pattern: dict[str, Any]
    actor_resource: dict[str, Any]
    sensitivity: Any


class BehavioralProfiler:
    """Profile sessions into structured behavioral features (no verdicts)."""

    def __init__(
        self,
        engine: BaselineEngine | None = None,
        config: DetectorConfig | None = None,
    ) -> None:
        self._engine = engine or BaselineEngine()
        self._config = config or DetectorConfig()
        self._last_sequence_result: SequenceResult | None = None

    @property
    def engine(self) -> BaselineEngine:
        return self._engine

    @property
    def last_sequence_result(self) -> SequenceResult | None:
        """The most recent sequence assessment (for tests/inspection)."""
        return self._last_sequence_result

    # ------------------------------------------------------------------
    # history recording (poisoning-gated; callers pass the gate explicitly)
    # ------------------------------------------------------------------

    def record_history(
        self,
        events: Sequence,
        sessions: Sequence[DataAccessSession],
        *,
        influence: BaselineInfluence = BaselineInfluence.ELIGIBLE,
        risk: str = "low",
    ) -> None:
        """Record session aggregates into the baseline engine.

        ``influence`` implements baseline poisoning protection: only
        ELIGIBLE observations shape trusted statistics; LIMITED/BLOCKED
        are recorded for audit only.
        """
        for session in sessions:
            ts = session.end_time_epoch_ms or 0.0
            entity = session.actor_id or "unknown"
            primary_bytes = (
                max((m.value for m in session.bytes_accessed.measurements), default=0.0)
                if session.bytes_accessed is not None
                else 0.0
            )
            duration_s = (
                ((session.end_time_epoch_ms or 0.0) - (session.start_time_epoch_ms or 0.0)) / 1000.0
            )
            self._engine.record("actor", "bytes", entity, primary_bytes, ts, influence=influence, risk=risk)
            self._engine.record("actor", "objects", entity, float(session.objects_accessed), ts, influence=influence, risk=risk)
            self._engine.record("actor", "requests", entity, float(session.request_count), ts, influence=influence, risk=risk)
            self._engine.record("actor", "resources", entity, float(len(session.resources_accessed)), ts, influence=influence, risk=risk)
            self._engine.record("actor", "destinations", entity, float(len(session.unique_destinations)), ts, influence=influence, risk=risk)
            self._engine.record("actor", "duration_s", entity, max(0.0, duration_s), ts, influence=influence, risk=risk)
            record_time_history(self._engine, session)

    # ------------------------------------------------------------------
    # profiling
    # ------------------------------------------------------------------

    def profile(
        self,
        session: DataAccessSession,
        events: Sequence,
        context: IntelligenceContext | None = None,
    ) -> BehavioralProfileResult:
        """Compute the full behavioral feature set for one session."""
        context = context or IntelligenceContext()
        now_ms = session.end_time_epoch_ms or _utcnow_ms()
        actor = session.actor_id or "unknown"

        if context.workload_id:
            session.session_features["workload_id"] = context.workload_id

        volume = volume_deviations(
            events,
            self._engine,
            scope="actor",
            scope_fn=lambda e: e.actor_id,
            scope_key=actor,
            end_epoch_ms=now_ms,
            peer_group=context.peer_group,
        )

        destinations = assess_destinations(session, context.known_destinations)

        history_sequences = self._actor_sequence_history(session, events)
        sequence_result = score_sequence(
            session_action_sequence(session, events),
            history_sequences,
        )
        sequence_result.session_id = session.session_id
        self._last_sequence_result = sequence_result

        time_assessment = time_anomaly(
            session, self._engine, context.schedules, at_epoch_ms=session.start_time_epoch_ms
        )

        egress = egress_signals(session)
        pattern_signals = access_pattern_signals(session, events, context.known_access)
        relationship = actor_resource_signals(
            session,
            context.actor_resource_history,
            resource_business_units=context.resource_business_units,
            actor_business_unit=context.actor_business_unit,
        )
        sensitivity = sensitivity_signals(
            session,
            resource_sensitivity=context.resource_sensitivity,
            resource_criticality=context.resource_criticality,
        )

        features = self._assemble(
            session,
            volume=volume,
            destinations=destinations,
            sequence_result=sequence_result,
            time=time_assessment,
            egress=egress,
            pattern_signals=pattern_signals,
            relationship=relationship,
            sensitivity=sensitivity,
        )

        return BehavioralProfileResult(
            features=features,
            volume=volume,
            destinations=destinations,
            sequence=sequence_result,
            time=time_assessment,
            egress=egress,
            access_pattern=pattern_signals,
            actor_resource=relationship,
            sensitivity=sensitivity,
        )

    # ------------------------------------------------------------------

    def _actor_sequence_history(
        self,
        session: DataAccessSession,
        events: Sequence,
    ) -> list[list[str]]:
        """This actor's previous action sequences (gap-split pseudo-sessions),
        excluding the current session's own events."""
        actor = session.actor_id
        if not actor:
            return []
        current_ids = set(session.event_ids)
        actor_events = sorted(
            (e for e in events if e.actor_id == actor and e.event_id not in current_ids),
            key=lambda e: e.event_time_epoch_ms or 0.0,
        )
        if not actor_events:
            return []
        gap_ms = self._config.session.inactivity_gap * 1000.0
        sequences: list[list[str]] = []
        current: list[str] = []
        last_ts = None
        for event in actor_events:
            ts = event.event_time_epoch_ms or 0.0
            if last_ts is not None and (ts - last_ts) > gap_ms:
                if current:
                    sequences.append(current)
                current = []
            current.append(event.data_action.value)
            last_ts = ts
        if current:
            sequences.append(current)
        return sequences

    def _assemble(
        self,
        session: DataAccessSession,
        *,
        volume: VolumeDeviations,
        destinations: DestinationAssessment,
        sequence_result: SequenceResult,
        time: Any,
        egress: Any,
        pattern_signals: dict[str, Any],
        relationship: dict[str, Any],
        sensitivity: Any,
    ) -> BehavioralFeatureSet:
        fset = BehavioralFeatureSet(
            subject_id=session.actor_id or "unknown",
            session_id=session.session_id,
            actor_id=session.actor_id,
            computed_at_epoch_ms=_utcnow_ms(),
        )

        # --- volume family ---------------------------------------------------
        def _volume_feature(score: float | None, detail: dict) -> AvailableFeature:
            if score is None:
                return AvailableFeature(
                    availability=FeatureAvailability.UNAVAILABLE,
                    provenance=volume.baseline_source,
                    detail=detail,
                )
            availability = (
                FeatureAvailability.OBSERVED
                if volume.baseline_source == "personal"
                else FeatureAvailability.ESTIMATED
            )
            return AvailableFeature(
                value=score,
                availability=availability,
                provenance=volume.baseline_source,
                detail=detail,
            )

        fset.volume_score = _volume_feature(
            volume.volume_deviation, {"windows": sorted(volume.windows.keys())}
        )
        fset.object_count_score = _volume_feature(volume.object_count_deviation, {})
        fset.request_rate_score = _volume_feature(volume.request_rate_deviation, {})

        # --- destination -------------------------------------------------------
        novelty_components = {
            "destination_novelty": destinations.destination_novelty,
            "asn_novelty": destinations.asn_novelty,
            "country_novelty": destinations.country_novelty,
            "provider_novelty": destinations.provider_novelty,
        }
        novelty = [v for v in novelty_components.values() if v is not None]
        common_destination_detail = {
            "worst_class": destinations.worst_class,
            "class_counts": destinations.class_counts,
            **{k: v for k, v in novelty_components.items()},
        }
        if novelty:
            fset.destination_score = AvailableFeature(
                value=max(novelty),
                availability=FeatureAvailability.OBSERVED,
                provenance="known_universe",
                detail=common_destination_detail,
            )
        else:
            fset.destination_score = AvailableFeature(
                availability=FeatureAvailability.UNAVAILABLE,
                provenance="known_universe",
                detail=common_destination_detail,
            )

        # --- access pattern (+ sequence folded into detail/value) --------------
        ap_score = access_pattern_score(pattern_signals)
        pattern_detail = dict(pattern_signals)
        pattern_detail["access_sequence_score"] = sequence_result.access_sequence_score
        pattern_detail["sequence_availability"] = sequence_result.availability
        pattern_detail["novel_ngrams"] = sequence_result.novel_ngrams

        candidates = [c for c in (ap_score, sequence_result.access_sequence_score) if c is not None]
        if candidates:
            fset.access_pattern_score = AvailableFeature(
                value=max(candidates),
                availability=FeatureAvailability.OBSERVED,
                provenance="access_universe",
                detail=pattern_detail,
            )
        else:
            fset.access_pattern_score = AvailableFeature(
                availability=FeatureAvailability.UNAVAILABLE,
                provenance="access_universe",
                detail=pattern_detail,
            )

        # --- sensitivity --------------------------------------------------------
        if sensitivity.sensitivity_score is None:
            fset.sensitivity_score = AvailableFeature(
                availability=FeatureAvailability.UNAVAILABLE,
                provenance=sensitivity.sensitivity_source,
                detail=sensitivity.detail,
            )
        else:
            fset.sensitivity_score = AvailableFeature(
                value=sensitivity.sensitivity_score,
                availability=FeatureAvailability.OBSERVED,
                provenance=sensitivity.sensitivity_source,
                detail={"business_criticality": sensitivity.business_criticality, **sensitivity.detail},
            )

        # --- time -----------------------------------------------------------------
        if time.time_score is None:
            fset.time_score = AvailableFeature(
                availability=FeatureAvailability.UNAVAILABLE,
                provenance=time.status,
                detail={"status": time.status, "matched_schedule": time.matched_schedule},
            )
        else:
            fset.time_score = AvailableFeature(
                value=time.time_score,
                availability=FeatureAvailability.OBSERVED,
                provenance=time.status,
                detail={
                    "status": time.status,
                    "matched_schedule": time.matched_schedule,
                    "min_hour_distance": time.min_hour_distance,
                    "weekday_novel": time.weekday_novel,
                },
            )

        # --- actor-resource ---------------------------------------------------------
        ar_novelty = relationship.get("actor_resource_novelty")
        if ar_novelty is None and not relationship.get("history_available"):
            fset.actor_resource_score = AvailableFeature(
                availability=FeatureAvailability.UNAVAILABLE,
                provenance="actor_resource_history",
                detail=relationship,
            )
        else:
            fset.actor_resource_score = AvailableFeature(
                value=ar_novelty if ar_novelty is not None else 0.0,
                availability=FeatureAvailability.OBSERVED,
                provenance="actor_resource_history",
                detail=relationship,
            )

        # --- egress --------------------------------------------------------------------
        if egress.egress_ratio is None:
            fset.egress_score = AvailableFeature(
                availability=FeatureAvailability.UNAVAILABLE,
                provenance="network_telemetry",
                detail={
                    "reliability": egress.reliability,
                    "network_egress_bytes": egress.network_egress_bytes,
                    "external_egress_ratio": egress.external_egress_ratio,
                },
            )
        else:
            fset.egress_score = AvailableFeature(
                value=min(1.0, egress.egress_ratio),
                availability=(
                    FeatureAvailability.OBSERVED if egress.availability == "observed"
                    else FeatureAvailability.ESTIMATED
                ),
                provenance="network_telemetry",
                detail={
                    "egress_ratio": egress.egress_ratio,
                    "external_egress_ratio": egress.external_egress_ratio,
                    "network_egress_bytes": egress.network_egress_bytes,
                    "data_access_bytes": egress.data_access_bytes,
                },
            )

        # --- baseline quality / scope -----------------------------------------------------
        fset.baseline_quality = volume.baseline_quality
        fset.baseline_scope_used = volume.baseline_source
        fset.cold_start = volume.baseline_source != "personal"

        return fset.finalize()


def _utcnow_ms() -> float:
    return datetime.now(timezone.utc).timestamp() * 1000.0
