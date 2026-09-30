"""Adversarial / robustness harness (safe, synthetic, replayed only).

Runs corrupted-telemetry scenarios against the ARDE validator and
measures whether the detector becomes **excessively confident** when
evidence degrades. A confident verdict on corrupted evidence is a
failure mode, not a success.

Scenario families (all synthetic; nothing here touches real systems):

- missing destination fields
- missing byte counts
- corrupted timestamps
- abnormal feature combinations
- incomplete telemetry
- noisy location metadata
- baseline contamination
- artificially inflated request counts
- contradictory telemetry sources

Excessive confidence test: after corruption, the finding must NOT be
more robust / more passing than the intact baseline. If corruption
*raises* robustness or flips a warning into PASSED, the harness flags
``excessive_confidence``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import (
    AvailableFeature,
    BehavioralFeatureSet,
    FeatureAvailability,
)
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession

from .models import ValidationStatus
from .validator import ARDEValidator

Corruptor = Callable[[DataAccessSession], DataAccessSession]
"""Pure function: returns a corrupted COPY of the session."""


@dataclass
class RobustnessScenario:
    """One adversarial scenario definition."""

    name: str
    description: str
    corruptor: Corruptor


@dataclass
class ScenarioResult:
    scenario: str
    base_status: str
    corrupted_status: str
    base_robustness: float
    corrupted_robustness: float
    excessive_confidence: bool
    """True when corruption made the finding MORE confident."""
    detail: dict[str, Any] = field(default_factory=dict)
    compare: str = "full"
    """``full``: robustness + status must not improve. ``status_only``:
    only a status upgrade counts (used where the robustness score
    legitimately tracks the corrupted quantity, e.g. baseline quality)."""


@dataclass
class RobustnessReport:
    results: list[ScenarioResult] = field(default_factory=list)

    @property
    def failures(self) -> list[ScenarioResult]:
        return [r for r in self.results if r.excessive_confidence]

    @property
    def passed(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_count": len(self.results),
            "excessive_confidence_count": len(self.failures),
            "passed": self.passed,
            "results": [
                {
                    "scenario": r.scenario,
                    "base_status": r.base_status,
                    "corrupted_status": r.corrupted_status,
                    "base_robustness": r.base_robustness,
                    "corrupted_robustness": r.corrupted_robustness,
                    "excessive_confidence": r.excessive_confidence,
                    "detail": r.detail,
                }
                for r in self.results
            ],
        }


# ---------------------------------------------------------------------------
# corruptors (pure: they copy, never mutate the input)
# ---------------------------------------------------------------------------


def strip_destinations(session: DataAccessSession) -> DataAccessSession:
    s = session.model_copy(deep=True)
    s.unique_destinations = []
    s.unique_asns = []
    s.unique_countries = []
    return s


def strip_bytes(session: DataAccessSession) -> DataAccessSession:
    s = session.model_copy(deep=True)
    s.bytes_accessed = None
    return s


def corrupt_timestamps(session: DataAccessSession) -> DataAccessSession:
    """End before start (classic clock corruption)."""
    s = session.model_copy(deep=True)
    if s.start_time_epoch_ms is not None and s.end_time_epoch_ms is not None:
        s.start_time_epoch_ms, s.end_time_epoch_ms = s.end_time_epoch_ms, s.start_time_epoch_ms
    else:
        s.end_time_epoch_ms = (s.start_time_epoch_ms or 0.0) - 10_000.0
    return s


def future_timestamps(session: DataAccessSession) -> DataAccessSession:
    """Timestamps far in the future (broken clock / replay forgery)."""
    s = session.model_copy(deep=True)
    offset = 10.0 * 365.25 * 24 * 3600 * 1000.0  # a decade ahead
    if s.start_time_epoch_ms is not None:
        s.start_time_epoch_ms += offset
    if s.end_time_epoch_ms is not None:
        s.end_time_epoch_ms += offset
    return s


def drop_actor(session: DataAccessSession) -> DataAccessSession:
    s = session.model_copy(deep=True)
    s.actor_id = None
    return s


def inflate_requests(session: DataAccessSession) -> DataAccessSession:
    """Artificially inflated request counts (log flooding / forgery)."""
    s = session.model_copy(deep=True)
    s.request_count = s.request_count * 100 + 5_000
    s.event_count = s.event_count * 10 + 100
    return s


def contradictory_telemetry(session: DataAccessSession) -> DataAccessSession:
    """Conflicting volume sources (flow says 1000x the data events)."""
    s = session.model_copy(deep=True)
    from algo.data_exfiltration.data_exfiltration.measurement import (
        MeasurementConfidence,
        MeasurementSource,
        SourceMeasurement,
    )

    if s.bytes_accessed is not None and s.bytes_accessed.measurements:
        base_value = s.bytes_accessed.value or 0.0
        s.bytes_accessed = s.bytes_accessed.add(
            SourceMeasurement(
                value=base_value * 1000.0,
                source=MeasurementSource.VPC_FLOW_LOG,
                confidence=MeasurementConfidence.OBSERVED,
                detail="synthetic contradiction injected by robustness harness",
            )
        )
    return s


def noisy_location(session: DataAccessSession) -> DataAccessSession:
    """Noisy geo metadata: random unrelated countries appear."""
    s = session.model_copy(deep=True)
    s.unique_countries = ["XX", "YY", s.unique_countries[0] if s.unique_countries else "ZZ"]
    return s


def contaminated_baseline(session: DataAccessSession) -> DataAccessSession:
    """Simulates a poisoned baseline by marking the feature set's baseline
    as trusted while history is thin. Applied at feature level by the
    runner (sessions do not carry baselines)."""
    return session.model_copy(deep=True)


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

_BASE_SCENARIOS: tuple[tuple[str, str, Corruptor], ...] = (
    ("missing_destination_fields", "all destination/ASN/country telemetry removed", strip_destinations),
    ("missing_byte_counts", "byte measurements removed", strip_bytes),
    ("corrupted_timestamps", "end time before start time", corrupt_timestamps),
    ("future_timestamps", "session timestamp one year in the future", future_timestamps),
    ("missing_actor_identity", "actor id removed", drop_actor),
    ("inflated_request_counts", "request/event counts inflated 10-100x", inflate_requests),
    ("contradictory_telemetry_sources", "flow bytes contradict data-event bytes 1000x", contradictory_telemetry),
    ("noisy_location_metadata", "implausible country noise injected", noisy_location),
)


class RobustnessHarness:
    """Runs corruption scenarios and detects excessive confidence."""

    def __init__(self, validator: ARDEValidator | None = None) -> None:
        self._validator = validator or ARDEValidator()

    @property
    def validator(self) -> ARDEValidator:
        return self._validator

    def run(
        self,
        *,
        session: DataAccessSession,
        scored: ScoredSession | None = None,
        fset: BehavioralFeatureSet | None = None,
        finding: Any = None,
        scenarios: list[RobustnessScenario] | None = None,
        feature_corruptors: dict[str, Callable[[BehavioralFeatureSet], BehavioralFeatureSet]] | None = None,
    ) -> RobustnessReport:
        """Execute the default (or supplied) scenarios.

        ``finding`` may be a minimal stub exposing ``finding_id`` and
        ``session_id``; the harness never mutates it.
        """
        finding = finding or _StubFinding(session.session_id)
        report = RobustnessReport()

        base_outcome = self._validator.validate(
            finding,
            session=session,
            scored=scored,
            fset=fset,
        )
        base_status = base_outcome.validation_status
        base_rob = base_outcome.robustness_score

        selected = scenarios if scenarios is not None else self.default_scenarios()
        for scenario in selected:
            corrupted_session = scenario.corruptor(session)
            corrupted_fset = fset
            if feature_corruptors and scenario.name in feature_corruptors:
                corrupted_fset = feature_corruptors[scenario.name](fset) if fset is not None else None

            outcome = self._validator.validate(
                finding,
                session=corrupted_session,
                scored=scored,
                fset=corrupted_fset,
            )
            excessive = self._is_excessive(base_outcome, outcome)
            report.results.append(
                ScenarioResult(
                    scenario=scenario.name,
                    base_status=base_status.value,
                    corrupted_status=outcome.validation_status.value,
                    base_robustness=base_rob,
                    corrupted_robustness=outcome.robustness_score,
                    excessive_confidence=excessive,
                    detail={"description": scenario.description},
                )
            )

        # baseline-contamination scenario lives at feature level
        if fset is not None:
            report.results.append(
                self._contamination_case(finding, session, scored, fset, base_outcome)
            )
        return report

    def default_scenarios(self) -> list[RobustnessScenario]:
        return [
            RobustnessScenario(name=name, description=desc, corruptor=fn)
            for name, desc, fn in _BASE_SCENARIOS
        ]

    # ------------------------------------------------------------------

    def _contamination_case(
        self,
        finding: Any,
        session: DataAccessSession,
        scored: ScoredSession | None,
        fset: BehavioralFeatureSet,
        base_outcome: Any,
    ) -> ScenarioResult:
        """Baseline contamination: pretend the thin/cold baseline is warm
        and trusted, then verify the validator does not get MORE confident
        than with the honest baseline."""
        inflated = fset.model_copy(deep=True)
        inflated.baseline_quality = 1.0
        inflated.baseline_scope_used = "personal"
        inflated.cold_start = False
        for name in (
            "volume_score", "object_count_score", "request_rate_score",
            "destination_score", "access_pattern_score", "sensitivity_score",
            "time_score", "actor_resource_score", "egress_score",
        ):
            feat: AvailableFeature = getattr(inflated, name)
            if feat.availability is FeatureAvailability.ESTIMATED:
                feat.availability = FeatureAvailability.OBSERVED

        outcome = self._validator.validate(
            finding, session=session, scored=scored, fset=inflated
        )
        excessive = self._is_excessive(base_outcome, outcome, status_only=True)
        return ScenarioResult(
            scenario="baseline_contamination",
            base_status=base_outcome.validation_status.value,
            corrupted_status=outcome.validation_status.value,
            base_robustness=base_outcome.robustness_score,
            corrupted_robustness=outcome.robustness_score,
            excessive_confidence=excessive,
            detail={"description": "thin baseline inflated to trusted; confidence must not rise"},
            compare="status_only",
        )

    @staticmethod
    def _is_excessive(
        base_outcome: Any,
        outcome: Any,
        *,
        status_only: bool = False,
    ) -> bool:
        """Corruption is 'excessive confidence' when it RAISES robustness
        or upgrades the validation status toward PASSED.

        ``status_only=True`` skips the robustness comparison — used where
        the robustness score deliberately tracks the corrupted quantity
        (baseline quality), so only a status upgrade is meaningful.
        """
        if outcome is None or base_outcome is None:
            return False
        base_status = base_outcome.validation_status
        base_rob = base_outcome.robustness_score
        if not status_only and outcome.robustness_score > base_rob + 1e-9:
            return True
        return _status_rank(outcome.validation_status) < _status_rank(base_status)


class _StubFinding:
    """Minimal finding stand-in for pure validator harness runs."""

    def __init__(self, session_id: str) -> None:
        self.finding_id = f"robustness-{session_id}"
        self.session_id = session_id
        self.severity = None
        self.observed_at_epoch_ms = 0.0


def _status_rank(status: ValidationStatus) -> int:
    """Lower = more confident. PASSED(0) ... REJECTED(3)."""
    return {
        ValidationStatus.PASSED: 0,
        ValidationStatus.PASSED_WITH_WARNINGS: 1,
        ValidationStatus.REVIEW_REQUIRED: 2,
        ValidationStatus.REJECTED: 3,
    }[status]
