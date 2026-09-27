"""Detector orchestration - **Part 2**.

Wires the whole deterministic-plus-ML pipeline::

    event -> features -> rules -> anomaly(MF) -> temporal
          -> fusion -> confidence -> severity -> finding | None

Detection modes:

* ``REAL_TIME`` - causal single-event scoring; ML disabled unless a fitted
  model is supplied.
* ``BATCH`` - identical scoring over a batch, plus baseline refresh hooks.
* ``REPLAY`` - deterministic re-scoring of historical events (two passes so
  temporal features never see the future). Required for evaluation.

The LLM never participates in this path; it may only *explain* a finding the
deterministic pipeline already produced.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence

from detection.credential_compromise import (
    baseline as baseline_engine,
)
from detection.credential_compromise.anomaly import (
    FEATURE_VERSION,
    IsolationForest,
    build_feature_vector,
)
from detection.credential_compromise.arde import ArdeInput, validate_finding
from detection.credential_compromise.audit import AuditLog
from detection.credential_compromise.config import DetectorConfig, load_config
from detection.credential_compromise.confidence import EvidenceContext, evidence_confidence
from detection.credential_compromise.explainability import build_explanation
from detection.credential_compromise.features import extract_features
from detection.credential_compromise.finding import build_finding, finalize_finding
from detection.credential_compromise.model_registry import ComponentVersions
from detection.credential_compromise.rules import evaluate_rules
from detection.credential_compromise.schemas import (
    IdentityActivityEvent,
    IdentityProfile,
    Severity,
)
from detection.credential_compromise.scorer import (
    ComponentScores,
    rule_signal_score,
    score_event,
    severity_for,
)
from detection.credential_compromise.suppression import SuppressionEngine
from detection.credential_compromise.temporal import (
    TemporalTracker,
    burst_score,
    temporal_anomaly_score,
    temporal_vector,
    WINDOW_MINUTES,
)


class DetectionMode(str, enum.Enum):
    REAL_TIME = "REAL_TIME"
    BATCH = "BATCH"
    REPLAY = "REPLAY"


@dataclass
class DetectionResult:
    """Everything the scoring produced for one event (finding-or-not)."""

    event_id: str
    risk: float
    confidence: float
    severity: Severity
    is_finding: bool
    signals: list = field(default_factory=list)
    features: Optional[Any] = None
    temporal: dict = field(default_factory=dict)
    anomaly_raw: Optional[float] = None
    anomaly_score: Optional[float] = None
    fusion_contributions: dict = field(default_factory=dict)
    versions: Optional[ComponentVersions] = None
    arde: Optional[Any] = None
    suppression: Optional[Any] = None
    finding: Optional[dict] = None


@dataclass
class _PrivateState:
    """Per-detector runtime state."""

    tracker: TemporalTracker = field(default_factory=TemporalTracker)
    personal_baseline_cache: dict = field(default_factory=dict)


class CredentialCompromiseDetector:
    """Entry point for Algorithm #1.

    Operates with or without a fitted Isolation Forest; with one, the ML score
    joins the ensemble as a *corroborating* component, never a majority one.
    """

    def __init__(
        self,
        config: DetectorConfig | None = None,
        *,
        anomaly_model: Optional[IsolationForest] = None,
        finding_threshold: float = 70.0,
    ) -> None:
        self.config = config or load_config()
        self.anomaly_model = anomaly_model
        self.finding_threshold = finding_threshold
        # A detector is a stateful, ordered stream processor: the temporal
        # tracker and any profile cache are internal and reset per instance.
        self._tracker = TemporalTracker(windows_minutes=WINDOW_MINUTES)
        self._profiles: dict[tuple[str, int], IdentityProfile] = {}
        self.audit_log = AuditLog()
        self.suppression = SuppressionEngine(audit_log=self.audit_log, config=self.config.suppression)
    # ------------------------------------------------------------------ #
    # Baseline management
    # ------------------------------------------------------------------ #

    def set_profile(self, profile: IdentityProfile) -> None:
        """Inject a built profile for the detector to score against."""
        self._profiles[(profile.identity_key, profile.window_days)] = profile

    def learn(self, events: Sequence[IdentityActivityEvent]) -> Optional[IdentityProfile]:
        """Batch-learn a personal baseline from historical (benign-trusted) events."""
        if not events:
            return None
        first = events[0]
        identity_key = first.identity_key or first.principal_id
        from detection.credential_compromise.profile import initial_profile

        profile = initial_profile(
            identity_key=identity_key,
            principal_id=first.principal_id,
            window_days=self.config.baseline.primary_window_days,
            account_id=first.account_id,
            principal_type=first.principal_type,
            identity_kind=first.identity_kind,
            baseline_category=first.baseline_category,
        )
        built = baseline_engine.build_profile(
            profile, events, config=self.config.baseline
        )
        self.set_profile(built)
        return built

    def observe_baseline(self, event: IdentityActivityEvent, event_risk: float) -> None:
        """Risk-aware online baseline update (poisoning-guarded)."""
        profile = self._profiles.get(
            (event.identity_key or event.principal_id, self.config.baseline.primary_window_days)
        )
        if profile is None:
            return
        updated = baseline_engine.update_profile(
            profile, event, event_risk=event_risk, config=self.config.baseline
        )
        self.set_profile(updated)

    # ------------------------------------------------------------------ #
    # Core scoring
    # ------------------------------------------------------------------ #

    def detect(
        self,
        event: IdentityActivityEvent,
        *,
        mode: DetectionMode = DetectionMode.REAL_TIME,
        session: Optional[Any] = None,
    ) -> DetectionResult:
        """Score one event and produce a finding when the threshold is met."""
        identity = event.identity_key or event.principal_id
        at = event.timestamp

        # Temporal features must reflect the event's own arrival (causal).
        windows_map = self._tracker.window_slices(identity, at=at)
        stats_5m = windows_map.get(5)
        stats_60m = windows_map.get(60)
        burst = burst_score(stats_5m, stats_60m) if stats_5m and stats_60m else 0.0
        t_score = temporal_anomaly_score(windows_map, burst=burst)
        result_temporal = temporal_vector(windows_map, burst=burst)

        profile = self._profiles.get((identity, self.config.baseline.primary_window_days))
        features = extract_features(
            event,
            profile,
            config=self.config.baseline,
            feature_config=self.config.features,
        )

        signals = evaluate_rules(
            event,
            features,
            config=self.config.baseline,
            feature_config=self.config.features,
            rule_config=self.config.rules,
        )

        anomaly_raw = None
        anomaly_score_value = 0.0
        if self.anomaly_model is not None and self.anomaly_model.fitted:
            vector = build_feature_vector(
                event,
                features,
                windows=windows_map,
                burst=burst,
                config=self.config.scoring,
                profile=profile,
                session=session,
            )
            anomaly_raw = self.anomaly_model.raw_score(vector.values)
            anomaly_score_value = self.anomaly_model.score_normalized(vector.values)

        rule_score = rule_signal_score(signals)
        components = ComponentScores(
            behavior=min(1.0, features_privilege_aware_behavior(features)),
            rule=rule_score,
            anomaly=anomaly_score_value,
            temporal=t_score,
            privilege=features.privilege_anomaly.value,
        )
        fusion = score_event(components, config=self.config.fusion)
        risk = fusion.risk

        touched = len(
            [value for name, value in features.dimension_values().items() if value >= 0.5]
        )
        evidence = EvidenceContext(
            baseline_quality=features.baseline_quality,
            is_peer_baseline=features.is_peer_baseline,
            corroborating_signals=len(signals),
            independent_dimensions_touched=touched,
            enrichment_completeness=_enrichment_completeness(event),
        )
        confidence = evidence_confidence(evidence, config=self.config.confidence)
        severity = severity_for(
            risk,
            confidence=confidence,
            corroborating_signals=len(signals),
        )

        self._tracker.observe(event)

        versions = ComponentVersions(
            baseline_version=profile.baseline_version if profile else 0,
        )
        result = DetectionResult(
            event_id=event.event_id,
            risk=risk,
            confidence=confidence,
            severity=severity,
            is_finding=False,
            signals=signals,
            features=features,
            temporal=result_temporal,
            anomaly_raw=anomaly_raw,
            anomaly_score=anomaly_score_value if self.anomaly_model else None,
            fusion_contributions=fusion.contributions,
            versions=versions,
        )
        if risk >= self.finding_threshold:
            result.is_finding = True
            detection_finding = build_finding(
                event=event,
                risk=risk,
                confidence=confidence,
                severity=severity,
                signals=signals,
                feature_evidence=features.to_evidence(),
                fusion_contributions=fusion.contributions,
                versions=versions,
                detection_mode=mode.value,
            )

            # ARDE: challenge the finding before it is trusted.
            signal_payloads = [
                s.to_dict() if hasattr(s, "to_dict") else dict(s) for s in signals
            ]
            arde_result = validate_finding(
                ArdeInput(
                    event=event,
                    features=features,
                    signals=tuple(signal_payloads),
                    rule_score=rule_score,
                    anomaly_score=anomaly_score_value,
                    anomaly_model_used=bool(self.anomaly_model and self.anomaly_model.fitted),
                    profile=profile,
                    is_peer_baseline=features.is_peer_baseline,
                    session=session,
                    temporal_windows=result_temporal,
                    event_risk=risk,
                    baseline_freeze_threshold=self.config.baseline.baseline_freeze_risk_threshold,
                ),
                config=self.config.arde,
            )
            result.arde = arde_result
            explanation = build_explanation(
                features,
                signal_payloads,
                arde_result,
                anomaly_score=anomaly_score_value,
                anomaly_model_used=bool(self.anomaly_model and self.anomaly_model.fitted),
            )

            # Suppression: governed, audited, never silent.
            suppression_decision = self.suppression.evaluate(
                identity_key=identity,
                rule_ids=[s.rule_id for s in signals],
                severity=severity,
            )
            result.suppression = suppression_decision
            self.audit_log.append(
                actor="detector",
                action="finding.validated",
                subject=detection_finding["finding_id"],
                payload={
                    "risk": risk,
                    "validation_status": arde_result.validation_status,
                    "robustness_score": arde_result.robustness_score,
                    "suppressed": suppression_decision.suppressed,
                    "downgraded_to_review": suppression_decision.downgraded_to_review,
                },
            )
            if suppression_decision.suppressed:
                result.is_finding = False
                result.finding = None
                return result

            severity_final = severity
            if suppression_decision.downgraded_to_review:
                severity_final = Severity.MEDIUM
            result.finding = finalize_finding(
                detection_finding=detection_finding,
                event=event,
                session=session,
                arde_result=arde_result,
                explanation=explanation,
                versions=versions,
                suppression_note=(
                    suppression_decision.explanation
                    if suppression_decision.matched_suppression_ids
                    else None
                ),
            )
            result.finding["severity"] = severity_final.value
            result.severity = severity_final
        return result

    # ------------------------------------------------------------------ #
    # Modes
    # ------------------------------------------------------------------ #

    def detect_batch(self, events: Sequence[IdentityActivityEvent]) -> list[DetectionResult]:
        """Score a batch in timestamp order per identity (BATCH mode)."""
        ordered = sorted(
            events,
            key=lambda e: (e.identity_key or e.principal_id, e.timestamp),
        )
        return [
            self.detect(event, mode=DetectionMode.BATCH) for event in ordered
        ]

    def replay(
        self,
        events: Sequence[IdentityActivityEvent],
        *,
        exclude_event_from_temporal: bool = True,
    ) -> list[DetectionResult]:
        """Deterministically re-score history (REPLAY mode).

        Temporal windows are rebuilt causally from the replayed stream itself;
        nothing from "the future" relative to an event's timestamp informs its
        score. ML is applied only when a fitted model is attached.
        """
        ordered = sorted(
            events,
            key=lambda e: (e.identity_key or e.principal_id, e.timestamp),
        )
        return [self.detect(e, mode=DetectionMode.REPLAY) for e in ordered]


def features_privilege_aware_behavior(features) -> float:
    """Behavior score: max of the non-privilege dimensions and their weighted mean.

    Keeps a single dominant dimension visible without letting the mean dilute
    it to invisibility; privilege is carried separately in the fusion.
    """
    dims = features.dimension_values()
    non_priv = [value for name, value in dims.items() if name != "privilege"]
    weights = (0.15, 0.20, 0.15, 0.10, 0.25)
    mean = sum(w * v for w, v in zip(weights, non_priv)) / sum(weights)
    return max(mean, max(non_priv))


def _enrichment_completeness(event: IdentityActivityEvent) -> float:
    """How much context actually arrived with the event (0..1)."""
    present = 0
    total = 5
    if event.source_ip:
        present += 1
    if event.country:
        present += 1
    if event.asn is not None:
        present += 1
    if event.user_agent:
        present += 1
    if event.mfa_authenticated is not None:
        present += 1
    return present / total


__all__ = [
    "CredentialCompromiseDetector",
    "DetectionMode",
    "DetectionResult",
]
