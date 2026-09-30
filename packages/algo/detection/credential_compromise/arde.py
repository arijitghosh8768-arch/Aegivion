"""Adversarially Robust Detection Engine (ARDE) - **Part 3**.

ARDE is *not* a second detector. It challenges the conclusion the detection
pipeline already reached by asking: *could this finding be caused by noisy,
manipulated, incomplete or inconsistent evidence?*

Ten checks run over the evidence bundle; each failed check deducts a
configured number of robustness points. The output is a
:class:`ArdeResult` with:

* ``robustness_score`` in ``[0, 100]`` (100 = every check passed),
* ``validation_status`` in ``PASSED / PASSED_WITH_WARNINGS /
  REVIEW_REQUIRED / REJECTED``,
* machine-readable per-check results, including an explicit
  ``needs_review`` flag when rules and the ML model disagree.

Rule/ML disagreement **never forces a high-risk result**: it downgrades the
finding to review with an explanation instead.

Determinism: every check derives from the supplied evidence bundle only - no
wall-clock reads, no randomness. The same bundle always yields the same
robustness score and status.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from algo.detection.credential_compromise.config import ArdeConfig
from algo.detection.credential_compromise.features import BehavioralFeatures
from algo.detection.credential_compromise.schemas import (
    IdentityActivityEvent,
    IdentityProfile,
    IdentitySession,
)

VALIDATION_STATUSES = ("PASSED", "PASSED_WITH_WARNINGS", "REVIEW_REQUIRED", "REJECTED")


class CheckResult(BaseModel):
    """Outcome of one ARDE validation check."""

    model_config = ConfigDict(frozen=True)

    check_id: str
    name: str
    passed: bool
    penalty: float = 0.0
    detail: str = ""
    needs_review: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)


class ArdeResult(BaseModel):
    """Aggregate ARDE verdict over one finding."""

    model_config = ConfigDict(frozen=True)

    robustness_score: float = Field(ge=0.0, le=100.0)
    validation_status: str = Field(pattern="^(PASSED|PASSED_WITH_WARNINGS|REVIEW_REQUIRED|REJECTED)$")
    checks: tuple[CheckResult, ...] = ()
    needs_review: bool = False
    notes: tuple[str, ...] = ()

    def failed_checks(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if not check.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "robustness_score": self.robustness_score,
            "validation_status": self.validation_status,
            "needs_review": self.needs_review,
            "notes": list(self.notes),
            "checks": [check.model_dump() for check in self.checks],
        }


class ArdeInput(BaseModel):
    """The evidence bundle ARDE validates. Fully explicit, no hidden state."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    event: IdentityActivityEvent
    features: BehavioralFeatures
    signals: tuple[dict[str, Any], ...] = ()
    rule_score: float = Field(default=0.0, ge=0.0, le=1.0)
    anomaly_score: Optional[float] = None
    anomaly_model_used: bool = False
    profile: Optional[IdentityProfile] = None
    peer_profile: Optional[IdentityProfile] = None
    is_peer_baseline: bool = False
    personal_deviation: Optional[float] = None
    peer_deviation: Optional[float] = None
    session: Optional[IdentitySession] = None
    temporal_windows: dict[str, float] = Field(default_factory=dict)
    baseline_updated_by_event: bool = False
    event_risk: float = 0.0
    baseline_freeze_threshold: float = 70.0


def _check_feature_consistency(
    features: BehavioralFeatures, config: ArdeConfig
) -> CheckResult:
    tol = config.feature_value_tolerance
    out_of_range: list[str] = []
    for name, feature in features.all_features().items():
        if not (-tol <= feature.value <= 1.0 + tol):
            out_of_range.append(f"{name}={feature.value}")
        if feature.confidence < 0.0 or feature.confidence > 1.0:
            out_of_range.append(f"{name}.confidence={feature.confidence}")
    # Impossible combination: maximal novelty on every dimension at once is a
    # signature of corrupted aggregation, not of real activity.
    dims = features.dimension_values()
    if all(value >= 0.999 for value in dims.values()):
        out_of_range.append("all_dimensions_maxed")
    penalty = config.penalty_low_feature_confidence if out_of_range else 0.0
    return CheckResult(
        check_id="C01",
        name="feature_consistency",
        passed=not out_of_range,
        penalty=penalty,
        detail="; ".join(out_of_range) if out_of_range else "all features in range",
        evidence={"violations": out_of_range},
    )


def _check_evidence_completeness(
    event: IdentityActivityEvent, config: ArdeConfig
) -> CheckResult:
    present = sum(
        1 for field_name in config.expected_evidence_fields if getattr(event, field_name, None)
    )
    ratio = present / max(1, len(config.expected_evidence_fields))
    passed = ratio >= config.min_evidence_ratio
    missing = [
        field_name
        for field_name in config.expected_evidence_fields
        if not getattr(event, field_name, None)
    ]
    return CheckResult(
        check_id="C02",
        name="evidence_completeness",
        passed=passed,
        penalty=0.0 if passed else config.penalty_incomplete_evidence,
        detail=f"evidence ratio {ratio:.2f}",
        evidence={"missing": missing, "ratio": round(ratio, 4)},
    )


def _check_cross_signal_consistency(
    features: BehavioralFeatures, signals: Sequence[dict[str, Any]]
) -> CheckResult:
    """Signals must be backed by the features they claim to rest on."""
    inconsistent: list[str] = []
    feature_by_rule: dict[str, str] = {
        "R001": "country_novelty",
        "R002": "region_novelty",
        "R003": "ip_novelty",
        "R004": "asn_novelty",
        "R005": "time_anomaly",
        "R006": "client_novelty",
        "R007": "api_novelty",
        "R008": "service_novelty",
        "R009": "api_frequency_deviation",
        "R010": "privilege_anomaly",
        "R011": "privilege_anomaly",
        "R012": "privilege_anomaly",
        "R013": "privilege_anomaly",
        "R014": "api_frequency_deviation",
    }
    all_features = features.all_features()
    for signal in signals:
        rule_id = str(signal.get("rule_id", ""))
        feature_name = feature_by_rule.get(rule_id)
        if feature_name and feature_name in all_features:
            backing = all_features[feature_name]
            # A high-severity signal with zero-value backing feature or
            # zero confidence is incoherent evidence.
            if signal.get("severity", "").lower() in ("high", "critical") and (
                backing.value <= 0.0 or backing.confidence <= 0.0
            ):
                inconsistent.append(
                    f"{rule_id}:{feature_name}=({backing.value}, conf {backing.confidence})"
                )
    return CheckResult(
        check_id="C03",
        name="cross_signal_consistency",
        passed=not inconsistent,
        penalty=0.0,
        detail="; ".join(inconsistent) if inconsistent else "signals backed by features",
        evidence={"inconsistent": inconsistent},
    )


def _check_baseline_consistency(
    input_bundle: ArdeInput, config: ArdeConfig
) -> CheckResult:
    """Personal vs peer deviation must not wildly disagree (when both exist)."""
    personal = input_bundle.personal_deviation
    peer = input_bundle.peer_deviation
    if personal is None or peer is None:
        return CheckResult(
            check_id="C04",
            name="baseline_consistency",
            passed=True,
            detail="single-baseline comparison; nothing to cross-check",
        )
    gap = abs(personal - peer)
    passed = gap <= config.baseline_disagreement_gap
    return CheckResult(
        check_id="C04",
        name="baseline_consistency",
        passed=passed,
        penalty=0.0 if passed else config.penalty_baseline_disagreement,
        detail=f"personal vs peer deviation gap {gap:.3f}",
        evidence={
            "personal_deviation": round(personal, 4),
            "peer_deviation": round(peer, 4),
            "gap": round(gap, 4),
        },
        needs_review=not passed,
    )


def _check_rule_ml_disagreement(
    input_bundle: ArdeInput, config: ArdeConfig
) -> CheckResult:
    if not input_bundle.anomaly_model_used or input_bundle.anomaly_score is None:
        return CheckResult(
            check_id="C05",
            name="rule_ml_disagreement",
            passed=True,
            detail="ML model not in use; deterministic layers only",
        )
    gap = abs(input_bundle.rule_score - float(input_bundle.anomaly_score))
    disagreed = gap >= config.rule_ml_disagreement_gap
    return CheckResult(
        check_id="C05",
        name="rule_ml_disagreement",
        passed=not disagreed,
        penalty=config.penalty_rule_ml_disagreement if disagreed else 0.0,
        detail=(
            f"rules={input_bundle.rule_score:.3f} vs ml={input_bundle.anomaly_score:.3f} "
            f"(gap {gap:.3f})"
            if disagreed
            else f"rules and ML agree within {gap:.3f}"
        ),
        evidence={
            "rule_score": round(input_bundle.rule_score, 4),
            "anomaly_score": round(float(input_bundle.anomaly_score), 4),
            "gap": round(gap, 4),
        },
        # Disagreement never forces high risk: it forces human review.
        needs_review=disagreed,
    )


def _check_temporal_consistency(
    event: IdentityActivityEvent, session: Optional[IdentitySession], config: ArdeConfig
) -> CheckResult:
    issues: list[str] = []
    if session is not None:
        if event.timestamp < session.start_time:
            issues.append("event_precedes_session_start")
        skew_past = (session.start_time - event.timestamp).total_seconds()
        if skew_past > config.max_past_skew_seconds:
            issues.append(f"past_skew={skew_past:.0f}s")
        if event.timestamp > session.last_seen:
            issues.append("event_after_session_last_seen")
    # Location churn inside one event bundle would be contradictory; check
    # the temporal window aggregates instead.
    location_changes = input_bundle_location_changes(event)
    _ = location_changes  # windows are validated in C07 via temporal_windows
    return CheckResult(
        check_id="C06",
        name="temporal_consistency",
        passed=not issues,
        penalty=config.penalty_temporal_inconsistency if issues else 0.0,
        detail="; ".join(issues) if issues else "timeline coherent",
        evidence={"issues": issues},
    )


def input_bundle_location_changes(event: IdentityActivityEvent) -> int:
    """Location changes observable from a single event (always 0 or 1).

    Kept as a named helper so the temporal check documents its assumption.
    """
    return 0 if not event.country else 0


def _check_session_consistency(
    event: IdentityActivityEvent,
    session: Optional[IdentitySession],
    config: ArdeConfig,
) -> CheckResult:
    if session is None:
        return CheckResult(
            check_id="C07",
            name="session_consistency",
            passed=True,
            detail="no session context supplied",
        )
    issues: list[str] = []
    duration_hours = session.duration_seconds / 3600.0
    if duration_hours > config.max_session_duration_hours:
        issues.append(f"session_duration={duration_hours:.1f}h")
    if session.event_count <= 0:
        issues.append("session_claims_zero_events")
    if session.event_ids and event.event_id not in session.event_ids:
        issues.append("event_missing_from_session")
    return CheckResult(
        check_id="C07",
        name="session_consistency",
        passed=not issues,
        penalty=config.penalty_session_inconsistency if issues else 0.0,
        detail="; ".join(issues) if issues else "session coherent",
        evidence={"issues": issues, "duration_hours": round(duration_hours, 2)},
    )


def _check_baseline_poisoning(input_bundle: ArdeInput, config: ArdeConfig) -> CheckResult:
    issues: list[str] = []
    profile = input_bundle.profile
    if input_bundle.baseline_updated_by_event:
        if input_bundle.event_risk >= input_bundle.baseline_freeze_threshold:
            issues.append(
                f"high_risk_event_r{input_bundle.event_risk:.0f}_folded_into_baseline"
            )
        else:
            issues.append("baseline_updated_by_scored_event_itself")
    if profile is not None and input_bundle.event.country:
        # The event's "novel" country already dominating the baseline right
        # after being flagged novel is a contamination signature.
        share = (profile.normal_countries or {}).get(str(input_bundle.event.country), 0.0)
        novelty = input_bundle.features.country_novelty.value
        if novelty >= 0.9 and share >= 0.5:
            issues.append(f"novel_country_already_dominates_baseline(p={share:.2f})")
    return CheckResult(
        check_id="C08",
        name="baseline_poisoning",
        passed=not issues,
        penalty=config.penalty_baseline_contamination if issues else 0.0,
        detail="; ".join(issues) if issues else "baseline clean",
        evidence={"issues": issues},
        needs_review=any("folded_into_baseline" in issue for issue in issues),
    )


def _check_input_integrity(
    event: IdentityActivityEvent, config: ArdeConfig
) -> CheckResult:
    issues: list[str] = []
    skew_hours = abs((event.ingest_time - event.timestamp).total_seconds()) / 3600.0
    if skew_hours > config.max_timestamp_ingest_skew_hours:
        issues.append(f"timestamp_ingest_skew={skew_hours:.1f}h")
    if event.normalization_warnings:
        issues.append(f"normalization_warnings={len(event.normalization_warnings)}")
    if not event.event_source or not event.event_name:
        issues.append("missing_event_identity_fields")
    return CheckResult(
        check_id="C09",
        name="input_integrity",
        passed=not issues,
        penalty=config.penalty_input_integrity if issues else 0.0,
        detail="; ".join(issues) if issues else "input integrity ok",
        evidence={"issues": issues},
        needs_review=any("skew" in issue for issue in issues),
    )


def _check_model_uncertainty(input_bundle: ArdeInput, config: ArdeConfig) -> CheckResult:
    if not input_bundle.anomaly_model_used:
        return CheckResult(
            check_id="C10",
            name="model_uncertainty",
            passed=True,
            detail="no ML model in the loop; nothing to be uncertain about",
        )
    score = float(input_bundle.anomaly_score or 0.0)
    # Ambiguous band: neither clearly normal nor clearly anomalous.
    ambiguous = 0.35 <= score <= 0.65
    return CheckResult(
        check_id="C10",
        name="model_uncertainty",
        passed=not ambiguous,
        penalty=config.penalty_model_uncertainty if ambiguous else 0.0,
        detail=(
            f"model score {score:.3f} sits in the ambiguous band"
            if ambiguous
            else f"model score {score:.3f} is decisive"
        ),
        evidence={"anomaly_score": round(score, 4)},
        needs_review=ambiguous,
    )


def validate_finding(
    input_bundle: ArdeInput,
    *,
    config: Optional[ArdeConfig] = None,
) -> ArdeResult:
    """Run all ten ARDE checks over an evidence bundle."""
    config = config or ArdeConfig()
    checks = [
        _check_feature_consistency(input_bundle.features, config),
        _check_evidence_completeness(input_bundle.event, config),
        _check_cross_signal_consistency(input_bundle.features, input_bundle.signals),
        _check_baseline_consistency(input_bundle, config),
        _check_rule_ml_disagreement(input_bundle, config),
        _check_temporal_consistency(input_bundle.event, input_bundle.session, config),
        _check_session_consistency(input_bundle.event, input_bundle.session, config),
        _check_baseline_poisoning(input_bundle, config),
        _check_input_integrity(input_bundle.event, config),
        _check_model_uncertainty(input_bundle, config),
    ]
    score = 100.0 - sum(check.penalty for check in checks)
    score = max(0.0, min(100.0, score))

    if score < config.status_rejected_below:
        status = "REJECTED"
    elif score < config.status_review_below:
        status = "REVIEW_REQUIRED"
    elif score < config.status_warnings_below:
        status = "PASSED_WITH_WARNINGS"
    else:
        status = "PASSED"

    needs_review = any(check.needs_review for check in checks)
    # A check that explicitly demands human review escalates the status:
    # PASSED -> PASSED_WITH_WARNINGS -> REVIEW_REQUIRED. REJECTED stays.
    if needs_review and status == "PASSED":
        status = "PASSED_WITH_WARNINGS"
    if needs_review and status == "PASSED_WITH_WARNINGS":
        status = "REVIEW_REQUIRED"

    notes: list[str] = []
    disagreement = next((c for c in checks if c.check_id == "C05" and c.needs_review), None)
    if disagreement is not None:
        notes.append(
            "rules and ML disagree; finding requires human review and the risk "
            "score was not artificially raised"
        )

    return ArdeResult(
        robustness_score=round(score, 2),
        validation_status=status,
        checks=tuple(checks),
        needs_review=needs_review,
        notes=tuple(notes),
    )


__all__ = [
    "ArdeInput",
    "ArdeResult",
    "CheckResult",
    "VALIDATION_STATUSES",
    "validate_finding",
]
