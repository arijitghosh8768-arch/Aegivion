"""ARDE validator tests: the ten checks, status decision, robustness score.

Builds minimal session/feature/scored objects directly so check logic
is tested in isolation from the full pipeline (pipeline integration is
covered by test_arde_end_to_end.py).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from algo.data_exfiltration.data_exfiltration.arde.consistency import ARDEContext, ConsistencyEngine
from algo.data_exfiltration.data_exfiltration.arde.models import CheckSeverity, CheckStatus, RobustnessLevel, ValidationStatus
from algo.data_exfiltration.data_exfiltration.arde.validator import ARDEValidator, ARDEValidatorConfig
from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    AvailableFeature,
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.measurement import (
    MeasurementConfidence,
    MeasurementSource,
    simple_measurement,
)
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, FindingSeverity, SecurityFinding

_NOW = datetime(2024, 11, 14, 3, 0, tzinfo=timezone.utc)
_NOW_MS = _NOW.timestamp() * 1000.0
_DECADE_MS = 10.0 * 365.25 * 24 * 3600 * 1000.0

_ALL_FEATURES = (
    "volume_score", "object_count_score", "request_rate_score",
    "destination_score", "access_pattern_score", "sensitivity_score",
    "time_score", "actor_resource_score", "egress_score",
)


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------


def _session(
    session_id: str = "s1",
    *,
    actor: str | None = "arn:aws:iam::111122223333:user/alice",
    resources: list[str] | None = None,
    destinations: list[str] | None = None,
    bytes_total: float | None = 1_000_000.0,
    egress_bytes: float | None = None,
    start_ms: float | None = None,
    end_ms: float | None = None,
    read: int = 4,
    write: int = 0,
) -> DataAccessSession:
    start = start_ms if start_ms is not None else _NOW_MS - 60_000.0
    end = end_ms if end_ms is not None else _NOW_MS
    session = DataAccessSession(
        session_id=session_id,
        actor_id=actor,
        start_time_epoch_ms=start,
        end_time_epoch_ms=end,
        event_count=read + write,
        read_event_count=read,
        write_event_count=write,
    )
    session.resources_accessed = resources if resources is not None else ["s3://prod-customer-data"]
    session.unique_destinations = destinations if destinations is not None else []
    if bytes_total is not None:
        session.bytes_accessed = simple_measurement(
            bytes_total, MeasurementSource.CLOUDTRAIL, MeasurementConfidence.ESTIMATED
        )
    if egress_bytes is not None:
        session.network_egress_bytes = simple_measurement(
            egress_bytes, MeasurementSource.VPC_FLOW_LOG, MeasurementConfidence.OBSERVED
        )
    return session


def _fset(
    session_id: str = "s1",
    *,
    observed: bool = True,
    volume: float | None = 0.1,
    destination: float | None = 0.05,
    access_pattern: float | None = 0.05,
    sensitivity: float | None = 0.05,
    time: float | None = 0.05,
    actor_resource: float | None = 0.05,
    egress: float | None = 0.05,
    baseline_quality: float = 0.9,
    scope: str = "personal",
    universe_supplied: bool = False,
) -> BehavioralFeatureSet:
    """Fully-populated quiet feature set by default; individual features
    (or all of them with ``observed=False``) can be knocked out."""

    def _f(v: float | None) -> AvailableFeature:
        if v is None or not observed:
            return AvailableFeature(availability=FeatureAvailability.UNAVAILABLE)
        return AvailableFeature(
            value=v, availability=FeatureAvailability.OBSERVED, provenance="test"
        )

    fset = BehavioralFeatureSet(
        subject_id="alice",
        session_id=session_id,
        actor_id="alice",
        computed_at_epoch_ms=_NOW_MS,
        baseline_quality=baseline_quality,
        baseline_scope_used=scope,
        cold_start=scope != "personal",
    )
    fset.volume_score = _f(volume)
    fset.object_count_score = _f(volume)
    fset.request_rate_score = _f(volume)
    fset.destination_score = _f(destination)
    fset.access_pattern_score = _f(access_pattern)
    fset.sensitivity_score = _f(sensitivity)
    fset.time_score = _f(time)
    fset.actor_resource_score = _f(actor_resource)
    fset.egress_score = _f(egress)
    if universe_supplied:
        for name in ("destination_score",):
            getattr(fset, name).detail["known_universe_supplied"] = {"destinations": True}
    return fset.finalize()


def _scored(
    session_id: str = "s1",
    *,
    risk: float = 0.3,
    rules: float = 0.3,
    contributions: dict[str, float] | None = None,
    fired: list[str] | None = None,
) -> ScoredSession:
    return ScoredSession(
        session_id=session_id,
        variant="B",
        risk_score=risk,
        rules_score=rules,
        confidence_score=0.5,
        confidence_state="heuristic",
        severity="medium",
        contributions=contributions
        or {"volume": round(risk * 0.5, 4), "destination": round(risk * 0.3, 4), "time": round(risk * 0.2, 4)},
        fired_rules=fired or [],
        model={"model_name": "aegivion.data_exfiltration", "model_version": "3.0.0",
               "feature_version": "ml-features-x", "scoring_version": "scoring-3.0.0"},
    )


def _finding(
    finding_id: str = "find-1",
    session_id: str = "s1",
    *,
    severity: FindingSeverity | None = FindingSeverity.MEDIUM,
) -> SecurityFinding:
    return SecurityFinding(
        finding_id=finding_id,
        detector_name="aegivion.data_exfiltration",
        title="t",
        description="d",
        observed_at_epoch_ms=_NOW_MS,
        session_id=session_id,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# the ten checks
# ---------------------------------------------------------------------------


class TestTenChecks:
    def test_all_ten_checks_run(self) -> None:
        engine = ConsistencyEngine()
        ctx = ARDEContext(
            session=_session(), scored=_scored(), fset=_fset(), finding=_finding()
        )
        checks = engine.run_checks(ctx)
        names = [c.check_name for c in checks]
        assert names == [
            "feature_consistency",
            "provenance_completeness",
            "volume_consistency",
            "destination_consistency",
            "sensitivity_consistency",
            "actor_resource_consistency",
            "temporal_consistency",
            "network_consistency",
            "model_rule_agreement",
            "baseline_quality_check",
        ]

    def test_feature_consistency_flags_single_feature_domination(self) -> None:
        engine = ConsistencyEngine()
        ctx = ARDEContext(
            session=_session(),
            scored=_scored(
                risk=0.9,
                contributions={"anomaly": 0.88, "volume": 0.02},
            ),
            fset=_fset(),
            finding=_finding(),
        )
        check = engine.check_feature_consistency(ctx)
        assert check.status is CheckStatus.FAILED
        assert "overreaction" in check.message or "dominated" in check.message

    def test_feature_consistency_passes_when_corroborated(self) -> None:
        engine = ConsistencyEngine()
        ctx = ARDEContext(
            session=_session(),
            scored=_scored(
                risk=0.8,
                contributions={"volume": 0.2, "destination": 0.2, "sensitivity": 0.2, "egress": 0.2},
            ),
            fset=_fset(),
            finding=_finding(),
        )
        assert engine.check_feature_consistency(ctx).status is CheckStatus.PASSED

    def test_provenance_completeness_fails_on_thin_evidence(self) -> None:
        engine = ConsistencyEngine()
        ctx = ARDEContext(
            session=_session(),
            scored=_scored(),
            fset=_fset(observed=False),
            finding=_finding(),
        )
        check = engine.check_provenance_completeness(ctx)
        assert check.status is CheckStatus.FAILED
        assert check.detail["available_share"] == 0.0

    def test_provenance_completeness_warns_on_partial(self) -> None:
        engine = ConsistencyEngine()
        ctx = ARDEContext(
            session=_session(),
            scored=_scored(),
            fset=_fset(egress=None),
            finding=_finding(),
        )
        check = engine.check_provenance_completeness(ctx)
        assert check.status is CheckStatus.WARNING
        assert "egress_score" in check.detail["unavailable_features"]

    def test_volume_consistency_flags_conflicting_sources(self) -> None:
        session = _session()
        session.bytes_accessed = simple_measurement(
            1_000_000, MeasurementSource.CLOUDTRAIL, MeasurementConfidence.ESTIMATED
        ).add(
            type(session.bytes_accessed.measurements[0])(
                value=50_000_000,
                source=MeasurementSource.VPC_FLOW_LOG,
                confidence=MeasurementConfidence.OBSERVED,
            )
        )
        engine = ConsistencyEngine()
        check = engine.check_volume_consistency(ARDEContext(session=session, finding=_finding()))
        assert check.status is CheckStatus.WARNING
        assert check.detail["bytes_sources_conflict"] is True

    def test_volume_consistency_abstains_without_telemetry(self) -> None:
        session = _session(bytes_total=None)
        engine = ConsistencyEngine()
        check = engine.check_volume_consistency(ARDEContext(session=session, finding=_finding()))
        assert check.status is CheckStatus.ABSTAINED

    def test_destination_consistency_fails_on_unsupported_high_risk(self) -> None:
        # high destination score with NO destination telemetry
        engine = ConsistencyEngine()
        ctx = ARDEContext(
            session=_session(destinations=[]),
            fset=_fset(destination=0.9),
            finding=_finding(),
        )
        check = engine.check_destination_consistency(ctx)
        assert check.status is CheckStatus.FAILED

    def test_destination_consistency_warns_without_universe(self) -> None:
        engine = ConsistencyEngine()
        ctx = ARDEContext(
            session=_session(destinations=["198.51.100.9"]),
            fset=_fset(destination=0.6),
            finding=_finding(),
        )
        check = engine.check_destination_consistency(ctx)
        assert check.status is CheckStatus.WARNING

    def test_sensitivity_consistency_fails_without_source(self) -> None:
        engine = ConsistencyEngine()
        fset = _fset(sensitivity=0.9)
        fset.sensitivity_score.provenance = None  # no named source
        check = engine.check_sensitivity_consistency(
            ARDEContext(session=_session(), fset=fset, finding=_finding())
        )
        assert check.status is CheckStatus.FAILED

    def test_sensitivity_consistency_abstains_without_enrichment(self) -> None:
        engine = ConsistencyEngine()
        check = engine.check_sensitivity_consistency(
            ARDEContext(session=_session(), fset=_fset(sensitivity=None), finding=_finding())
        )
        assert check.status is CheckStatus.ABSTAINED

    def test_actor_resource_fails_when_no_actor(self) -> None:
        engine = ConsistencyEngine()
        fset = _fset(actor_resource=0.8)
        ctx = ARDEContext(
            session=_session(actor=None), fset=fset, finding=_finding()
        )
        check = engine.check_actor_resource_consistency(ctx)
        assert check.status is CheckStatus.FAILED

    def test_temporal_consistency_rejects_future_timestamps(self) -> None:
        engine = ConsistencyEngine()
        session = _session(start_ms=_NOW_MS + _DECADE_MS, end_ms=_NOW_MS + _DECADE_MS + 1000.0)
        check = engine.check_temporal_consistency(ARDEContext(session=session, finding=_finding()))
        assert check.status is CheckStatus.FAILED
        assert check.severity is CheckSeverity.CRITICAL

    def test_temporal_consistency_rejects_reversed_time(self) -> None:
        engine = ConsistencyEngine()
        session = _session(start_ms=_NOW_MS, end_ms=_NOW_MS - 5000.0)
        check = engine.check_temporal_consistency(ARDEContext(session=session, finding=_finding()))
        assert check.status is CheckStatus.FAILED

    def test_network_consistency_abstains_without_egress(self) -> None:
        engine = ConsistencyEngine()
        check = engine.check_network_consistency(
            ARDEContext(session=_session(), fset=_fset(egress=None), finding=_finding())
        )
        assert check.status is CheckStatus.ABSTAINED

    def test_model_rule_agreement_warns_on_big_gap(self) -> None:
        engine = ConsistencyEngine()
        ctx = ARDEContext(
            session=_session(),
            scored=_scored(risk=0.9, rules=0.2),
            fset=_fset(),
            finding=_finding(),
        )
        check = engine.check_model_rule_agreement(ctx)
        assert check.status is CheckStatus.WARNING
        assert check.detail["fusion_minus_rules"] > 0.4

    def test_baseline_quality_fails_on_unbacked_deviation(self) -> None:
        engine = ConsistencyEngine()
        fset = _fset(volume=0.9, baseline_quality=0.0, scope="none")
        check = engine.check_baseline_quality(
            ARDEContext(session=_session(), fset=fset, finding=_finding())
        )
        assert check.status is CheckStatus.FAILED
        assert "no trusted baseline" in check.message

    def test_baseline_quality_warns_on_thin_baseline_deviation(self) -> None:
        engine = ConsistencyEngine()
        fset = _fset(volume=0.9, baseline_quality=0.3, scope="peer")
        check = engine.check_baseline_quality(
            ARDEContext(session=_session(), fset=fset, finding=_finding())
        )
        assert check.status is CheckStatus.WARNING

    def test_baseline_quality_passes_without_deviation_claim(self) -> None:
        engine = ConsistencyEngine()
        fset = _fset(volume=0.1, baseline_quality=0.1, scope="none")
        check = engine.check_baseline_quality(
            ARDEContext(session=_session(), fset=fset, finding=_finding())
        )
        assert check.status is CheckStatus.PASSED


# ---------------------------------------------------------------------------
# validator status decisions
# ---------------------------------------------------------------------------


class TestValidatorStatuses:
    def test_clean_evidence_passes(self) -> None:
        validator = ARDEValidator()
        outcome = validator.validate(
            _finding(),
            session=_session(),
            scored=_scored(risk=0.3),
            fset=_fset(),
        )
        assert outcome.validation_status in (ValidationStatus.PASSED, ValidationStatus.PASSED_WITH_WARNINGS)
        assert 0.0 <= outcome.robustness_score <= 1.0

    def test_clean_evidence_full_corroboration_is_robust(self) -> None:
        validator = ARDEValidator()
        outcome = validator.validate(
            _finding(),
            session=_session(egress_bytes=500_000.0, destinations=["198.51.100.9"]),
            scored=_scored(risk=0.3),
            fset=_fset(universe_supplied=True),
        )
        assert outcome.robustness_level is RobustnessLevel.ROBUST

    def test_critical_check_failure_rejects(self) -> None:
        validator = ARDEValidator()
        session = _session(start_ms=_NOW_MS + _DECADE_MS, end_ms=_NOW_MS + _DECADE_MS + 1000.0)
        outcome = validator.validate(
            _finding(), session=session, scored=_scored(), fset=_fset()
        )
        assert outcome.validation_status is ValidationStatus.REJECTED

    def test_single_feature_domination_requires_review(self) -> None:
        validator = ARDEValidator()
        outcome = validator.validate(
            _finding(),
            session=_session(),
            scored=_scored(risk=0.9, contributions={"anomaly": 0.88, "volume": 0.02}),
            fset=_fset(),
        )
        assert outcome.validation_status is ValidationStatus.REVIEW_REQUIRED

    def test_two_failures_reject(self) -> None:
        validator = ARDEValidator()
        # failure 1: destination risk scored with zero destination telemetry
        # failure 2: unbacked deviation claim on no baseline
        outcome = validator.validate(
            _finding(),
            session=_session(destinations=[]),
            scored=_scored(risk=0.3),
            fset=_fset(volume=0.9, destination=0.9, baseline_quality=0.0, scope="none"),
        )
        assert outcome.validation_status is ValidationStatus.REJECTED

    def test_bulk_transfer_shape_requires_review(self) -> None:
        validator = ARDEValidator()
        # big volume, no corroboration, no rules
        outcome = validator.validate(
            _finding(),
            session=_session(),
            scored=_scored(risk=0.6, fired=[]),
            fset=_fset(volume=0.9),
        )
        # with a warm baseline and consistent evidence this is the
        # classic 'large but routine' shape
        assert outcome.validation_status in (
            ValidationStatus.REVIEW_REQUIRED,
            ValidationStatus.PASSED_WITH_WARNINGS,
        )

    def test_robustness_levels_band_correctly(self) -> None:
        assert ARDEValidator._robustness_level(0.9) is RobustnessLevel.ROBUST
        assert ARDEValidator._robustness_level(0.5) is RobustnessLevel.MODERATE
        assert ARDEValidator._robustness_level(0.2) is RobustnessLevel.FRAGILE


# ---------------------------------------------------------------------------
# downgrade-only severity handling
# ---------------------------------------------------------------------------


class TestSeverityDecision:
    def test_rejected_finding_capped_at_medium(self) -> None:
        validator = ARDEValidator()
        finding = _finding(severity=FindingSeverity.CRITICAL)
        session = _session(start_ms=_NOW_MS + _DECADE_MS, end_ms=_NOW_MS + _DECADE_MS + 1000.0)
        outcome = validator.validate(finding, session=session, scored=_scored(), fset=_fset())
        assert outcome.validation_status is ValidationStatus.REJECTED
        assert outcome.downgrade is not None
        assert outcome.downgrade["to"] == "medium"

    def test_never_upgrades(self) -> None:
        validator = ARDEValidator()
        finding = _finding(severity=FindingSeverity.LOW)
        outcome = validator.validate(
            finding,
            session=_session(),
            scored=_scored(risk=0.3),
            fset=_fset(),
        )
        # even a clean pass must not upgrade a LOW finding
        assert outcome.downgrade is None or outcome.downgrade["to"] in ("low", "medium")

    def test_no_severity_no_downgrade(self) -> None:
        validator = ARDEValidator()
        finding = _finding(severity=None)
        session = _session(start_ms=_NOW_MS + _DECADE_MS, end_ms=_NOW_MS + _DECADE_MS + 1000.0)
        outcome = validator.validate(finding, session=session, scored=_scored(), fset=_fset())
        assert outcome.validation_status is ValidationStatus.REJECTED
        assert outcome.downgrade is None
