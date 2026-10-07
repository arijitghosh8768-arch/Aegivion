"""Top-level detector orchestration — **Part 3**.

Implements the full pipeline: ingest-independent canonical events →
sessionize → behavioral features (Part 2) → versioned ML feature vectors →
Isolation Forest anomaly → sequence model → risk fusion → confidence →
findings. FoundationPipeline (Part 1) is preserved unchanged for callers
that only need observational output.

Determinism contract: same events + same configuration + same versions ⇒
same findings (see :mod:`detection.cloud_destruction.replay`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from algo.detection.cloud_destruction.anomaly import IsolationForestModel
from algo.detection.cloud_destruction.arde import ArdeValidator, ValidationReport
from algo.detection.cloud_destruction.audit import AuditLogger
from algo.detection.cloud_destruction.baseline import (
    BaselineQuality,
    BaselineStore,
    classify_contamination,
)
from algo.detection.cloud_destruction.config import DestructionDetectorConfig
from algo.detection.cloud_destruction.confidence import ConfidenceConfig, ConfidenceResult, compute_confidence
from algo.detection.cloud_destruction.context import (
    ContextAnnotation,
    ContextEngine,
    ExceptionRegistry,
    apply_exceptions,
)
from algo.detection.cloud_destruction.evidence import collect_evidence
from algo.detection.cloud_destruction.explainability import (
    Explanation,
    build_explanation,
    categorize,
)
from algo.detection.cloud_destruction.feature_vector import build_ml_feature_vector
from algo.detection.cloud_destruction.features import SessionFeatureVector, extract_features
from algo.detection.cloud_destruction.finding import DestructionFinding, SeverityPolicy, build_finding
from algo.detection.cloud_destruction.legitimate import ApprovedActivityProfile
from algo.detection.cloud_destruction.registry import ModelRegistry
from algo.detection.cloud_destruction.resource_profile import ResourceProfileBuilder
from algo.detection.cloud_destruction.schemas import (
    DestructiveActivitySession,
    ResourceActivityEvent,
    ResourceProtectionProfile,
)
from algo.detection.cloud_destruction.scorer import (
    ScoringConfig,
    score_destruction,
)
from algo.detection.cloud_destruction.sequence_model import SequenceTransitionModel
from algo.detection.cloud_destruction.session import DestructiveSessionBuilder
from algo.detection.cloud_destruction.supervised import SupervisedDetector
from algo.detection.cloud_destruction.deviation import hour_span

__all__ = ["DetectionOutcome", "DestructionDetector", "FoundationPipeline"]


class _NullBaselineStore:
    """Variant switch: baseline-relative features report unavailable."""

    def get_or_build(self, actor_id, sessions, **kwargs):  # noqa: ANN001, ANN003
        return None


@dataclass
class DetectionOutcome:
    """Complete, audit-ready result of one detect() run."""

    sessions: list[DestructiveActivitySession]
    findings: list[DestructionFinding]
    feature_vectors: list[SessionFeatureVector]
    risks: list  # list[DestructionRisk]
    confidences: list[ConfidenceResult]
    anomaly_scores: dict[str, float]
    sequence_scores: dict[str, float]
    versions: dict[str, Any]
    raw: dict[str, Any] = field(default_factory=dict)

    # Part 6 — ARDE validation + explainability (aligned with findings)
    validation_reports: list[ValidationReport] = field(default_factory=list)
    explanations: list[Explanation] = field(default_factory=list)
    categories: list[tuple[str, ...]] = field(default_factory=list)
    context_annotations: list[ContextAnnotation] = field(
        default_factory=list
    )
    audit: dict[str, Any] = field(default_factory=dict)


class DestructionDetector:
    """Full detector: behavioral layer + ML anomaly + fusion + findings."""

    def __init__(
        self,
        config: Optional[DestructionDetectorConfig] = None,
        *,
        approved_profiles: Optional[Sequence[ApprovedActivityProfile]] = None,
        anomaly_seed: int = 1337,
        use_supervised: bool = False,
        supervised_detector: Optional[SupervisedDetector] = None,
        scoring_config: Optional[ScoringConfig] = None,
        confidence_config: Optional[ConfidenceConfig] = None,
        use_ml: bool = True,
        use_sequence_model: bool = True,
        use_baseline: bool = True,
        arde_validator: Optional[ArdeValidator] = None,
        context_engine: Optional[ContextEngine] = None,
        exception_registry: Optional[ExceptionRegistry] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self._config = config or DestructionDetectorConfig()
        self._approved_profiles = list(approved_profiles or [])
        self._anomaly_seed = anomaly_seed
        self._use_supervised = use_supervised
        self._supervised = supervised_detector
        self._scoring_config = scoring_config or ScoringConfig()
        self._confidence_config = confidence_config or ConfidenceConfig()
        # Variant switches for the comparative evaluation framework:
        # rules only / +baseline / +sequence / +ML / full detector.
        self._use_ml = use_ml
        self._use_sequence_model = use_sequence_model
        self._use_baseline = use_baseline
        # Part 6: ARDE validation, FP context, exceptions, audit.
        self._arde = arde_validator or ArdeValidator()
        self._exceptions = exception_registry or ExceptionRegistry()
        self._context = context_engine or ContextEngine(
            profiles=self._approved_profiles,
            exceptions=self._exceptions,
        )
        # NB: AuditLogger defines __len__, so ``audit_logger or ...``
        # would silently discard an injected (still empty) logger.
        self._audit = (
            AuditLogger() if audit_logger is None else audit_logger
        )
        self._registry = ModelRegistry()
        self._registry.register(IsolationForestModel(seed=anomaly_seed).descriptor())

    # ------------------------------------------------------------------ #
    # Detection
    # ------------------------------------------------------------------ #

    def detect(self, events: Sequence[ResourceActivityEvent]) -> DetectionOutcome:
        """Run the full detection pipeline over canonical events."""
        if not events:
            self._audit.log_detection_run(0, 0)
            return DetectionOutcome(
                sessions=[],
                findings=[],
                feature_vectors=[],
                risks=[],
                confidences=[],
                anomaly_scores={},
                sequence_scores={},
                versions=self._registry.to_dict(),
                audit=self._audit.to_log_dict(),
            )

        # 1) sessionize (Part 1)
        sessions = DestructiveSessionBuilder(self._config.session).build_sessions(list(events))
        per_session = self._match_events(sessions, events)
        self._audit.log_detection_run(len(events), len(sessions))

        # 2) behavioral features (Part 2) — leave-one-out baselines inside
        # (the ``use_baseline`` variant switch disables baseline-relative
        # features entirely: every deviation reports unavailable and the
        # scorer falls back to absolute pace/scope evidence)
        vectors = extract_features(
            sessions,
            list(events),
            approved_profiles=self._approved_profiles,
            config=self._config,
            baseline_store=_NullBaselineStore() if not self._use_baseline else None,
        )

        # 3) versioned ML feature vectors + evidence for every session
        ev_by_session = {
            session.session_id: collect_evidence(session, per_session.get(session.session_id) or None)
            for session in sessions
        }
        hours_by_session = {
            session.session_id: hour_span(
                ev_by_session[session.session_id].event_count,
                ev_by_session[session.session_id].duration_seconds,
                self._config.behavioral.min_session_seconds,
            )
            for session in sessions
        }
        ml_vectors = {
            v.session_id: build_ml_feature_vector(v, ev_by_session[v.session_id], hours_by_session[v.session_id])
            for v in vectors
        }

        # 4) Isolation Forest over all sessions (leave-self-out scoring:
        # the scored session is excluded from its own training rows)
        rows = [ml_vectors[v.session_id].to_array() for v in vectors]
        anomaly_scores: dict[str, float] = {}
        if rows and self._use_ml:
            for v in vectors:
                others = [r for other in vectors if other.session_id != v.session_id for r in [ml_vectors[other.session_id].to_array()]]
                training = others if len(others) >= 2 else rows
                model = IsolationForestModel(seed=self._anomaly_seed).fit(training)
                anomaly_scores[v.session_id] = model.score_row(ml_vectors[v.session_id].to_array())

        # 5) sequence transition model over trusted history
        seq_model = SequenceTransitionModel()
        sequence_scores: dict[str, float] = {}
        if self._use_sequence_model:
            for session in sessions:
                seq_model.observe(
                    session,
                    per_session.get(session.session_id, []),
                    contamination=classify_contamination(session, self._config.baseline),
                )
            sequence_scores = {
                session.session_id: seq_model.score(session, per_session.get(session.session_id, [])).score
                for session in sessions
            }

        # 6) risk fusion + confidence + findings per session
        risks = []
        confidences = []
        findings = []
        validation_reports = []
        explanations = []
        annotations = []
        category_lists = []
        baseline_versions = {
            v.session_id: v.baseline_version for v in vectors
        }
        for session, vector in zip(sessions, vectors):
            risk = score_destruction(
                session,
                vector,
                anomaly_score=anomaly_scores.get(session.session_id),
                supervised_probability=None,  # wired when a supervised model is supplied
                sequence_score=sequence_scores.get(session.session_id),
                config=self._scoring_config,
            )
            if self._use_supervised and self._supervised is not None and self._supervised.is_fitted:
                prediction = self._supervised.predict_row(ml_vectors[session.session_id].to_array())
                if prediction is not None:
                    risk = score_destruction(
                        session,
                        vector,
                        anomaly_score=anomaly_scores.get(session.session_id),
                        supervised_probability=prediction.probability,
                        sequence_score=sequence_scores.get(session.session_id),
                        config=self._scoring_config,
                    )

            confidence = compute_confidence(
                session,
                vector,
                risk,
                ml_vector=ml_vectors.get(session.session_id),
                baseline_quality=vector.baseline_quality,
                has_event_detail=bool(per_session.get(session.session_id)),
                model_agreement=risk.model_agreement,
                config=self._confidence_config,
            )
            risks.append(risk)
            confidences.append(confidence)

            recoverability_value = None
            if vector.recoverability is not None and vector.recoverability.available:
                recoverability_value = vector.recoverability.value

            finding = build_finding(
                session,
                risk,
                confidence,
                registry=self._registry,
                baseline_version=baseline_versions.get(session.session_id),
                baseline_quality=vector.baseline_quality,
                anomaly_model_name="isolation_forest" if rows else "rules_only",
                anomaly_model_version="1.0.0" if rows else "0",
                approved_activity=(
                    vector.approved_activity.model_dump()
                    if vector.approved_activity is not None
                    else None
                ),
                recoverability=recoverability_value,
                policy=SeverityPolicy(),
            )
            # 7) Part 6 — ARDE challenges the finding, legitimate-context
            #    recognition annotates it (never suppresses), behavior is
            #    categorized and the machine-readable explanation is built.
            report = self._arde.validate(
                finding,
                session,
                vector,
                risk,
                confidence,
                per_session.get(session.session_id) or (),
            )
            annotation = self._context.evaluate(
                finding,
                session,
                per_session.get(session.session_id) or (),
            )
            finding = apply_exceptions(finding, annotation)
            # the emitted finding is the annotated one: apply_exceptions
            # attaches the context annotation to ``raw`` without touching
            # risk, severity or confidence (exceptions annotate, never
            # suppress), so all scored fields are already final.
            findings.append(finding)
            categories = tuple(
                category.value
                for category in categorize(session, vector)
            )
            explanation = build_explanation(
                finding,
                session,
                vector,
                risk,
                confidence,
                per_session.get(session.session_id) or (),
                report=report,
                recognized_patterns=[
                    hit.activity.value for hit in annotation.recognized_patterns
                ],
                sequence_score=sequence_scores.get(session.session_id),
            )

            validation_reports.append(report)
            annotations.append(annotation)
            category_lists.append(categories)
            explanations.append(explanation)

            self._audit.log_validation(report)
            self._audit.log_context(annotation)
            self._audit.log_finding(
                finding.finding_id,
                session.session_id,
                severity=finding.severity.value,
                risk_score=finding.risk_score,
                confidence_score=finding.confidence_score,
                categories=categories,
            )

        outcome = DetectionOutcome(
            sessions=sessions,
            findings=findings,
            feature_vectors=vectors,
            risks=risks,
            confidences=confidences,
            anomaly_scores=anomaly_scores,
            sequence_scores=sequence_scores,
            versions=self._registry.to_dict(),
            raw={
                "ml_vectors": {k: v.to_log_dict() for k, v in ml_vectors.items()},
                "sequence_model": seq_model.descriptor(),
            },
            validation_reports=validation_reports,
            explanations=explanations,
            categories=category_lists,
            context_annotations=annotations,
            audit=self._audit.to_log_dict(),
        )
        return outcome

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _match_events(
        sessions: Sequence[DestructiveActivitySession],
        events: Sequence[ResourceActivityEvent],
    ) -> dict[str, list[ResourceActivityEvent]]:
        """Match canonical events to sessions by event id (session_id fallback)."""
        event_by_id = {e.event_id: e for e in events}
        matched: dict[str, list[ResourceActivityEvent]] = {}
        for session in sessions:
            hits = [event_by_id[eid] for eid in session.event_ids if eid in event_by_id]
            if not hits:
                hits = [e for e in events if e.session_id == session.session_id]
            matched[session.session_id] = hits
        return matched


class FoundationPipeline:
    """Part 1 foundation pipeline: ingest → normalize → sessionize → profile.

    Preserved for callers that only need observational output (sessions +
    protection profiles); no risk, no findings.
    """

    def __init__(self, config: Optional[DestructionDetectorConfig] = None) -> None:
        self._config = config or DestructionDetectorConfig()
        self._session_builder = DestructiveSessionBuilder(self._config.session)
        self._profile_builder = ResourceProfileBuilder(config=self._config.profile)

    def process(
        self, events: list[ResourceActivityEvent]
    ) -> tuple[list[DestructiveActivitySession], dict[str, ResourceProtectionProfile]]:
        sessions = self._session_builder.build_sessions(events)
        profiles = self._profile_builder.build_profiles(events)
        return sessions, profiles
