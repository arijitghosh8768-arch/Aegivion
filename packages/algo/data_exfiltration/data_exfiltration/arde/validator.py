"""ARDE validator: challenges candidate findings before release.

Pipeline position: Part 3 scoring -> **ARDE validation** -> finding
released to Threat Correlation / analysts.

The validator:
- runs the ten consistency checks (consistency.py),
- evaluates approved-activity profiles (exception system, always
  auditable, never silently suppressing),
- applies false-positive controls (contextual reasoning, not
  thresholds-only: a large transfer needs corroborating suspicious
  signals to stay loud),
- computes the robustness score and the final validation status.

Hard rules:
- ARDE never upgrades severity. It can hold at the scoring severity or
  downgrade (with an auditable ``downgrade`` record). It never deletes,
  never auto-dismisses, never revokes, never blocks.
- Every exception evaluation produces an audit record whether or not it
  matched.
- REJECTED findings remain visible: rejection is an assessment, not a
  deletion.
"""

from __future__ import annotations

from typing import Any

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, FindingSeverity, SecurityFinding

from .approved_activities import ApprovedActivityRegistry
from .consistency import ARDEContext, ConsistencyEngine
from .models import (
    CheckSeverity,
    CheckStatus,
    RobustnessLevel,
    ValidationCheckResult,
    ValidationOutcome,
    ValidationStatus,
)

_SEVERITY_ORDER = [
    FindingSeverity.INFO,
    FindingSeverity.LOW,
    FindingSeverity.MEDIUM,
    FindingSeverity.HIGH,
    FindingSeverity.CRITICAL,
]


class ARDEValidatorConfig:
    """Tuning knobs for the validator (documented, not 'optimal')."""

    def __init__(
        self,
        *,
        checks_required_for_pass: int = 8,
        failed_check_for_reject: int = 2,
        robustness_observed_bonus: float = 0.12,
        exception_requires_corroboration: bool = True,
        min_corroborating_signals: int = 2,
    ) -> None:
        self.checks_required_for_pass = checks_required_for_pass
        self.failed_check_for_reject = failed_check_for_reject
        self.robustness_observed_bonus = robustness_observed_bonus
        self.exception_requires_corroboration = exception_requires_corroboration
        self.min_corroborating_signals = min_corroborating_signals


class ARDEValidator:
    """Validates scored findings; produces auditable ValidationOutcomes."""

    def __init__(
        self,
        *,
        consistency: ConsistencyEngine | None = None,
        exceptions: ApprovedActivityRegistry | None = None,
        config: ARDEValidatorConfig | None = None,
        audit_log: Any = None,
    ) -> None:
        self._consistency = consistency or ConsistencyEngine()
        self._exceptions = exceptions
        self._config = config or ARDEValidatorConfig()
        self._audit_log = audit_log

    @property
    def audit_log(self) -> Any:
        return self._audit_log

    # ------------------------------------------------------------------

    def validate(
        self,
        finding: SecurityFinding,
        *,
        session: DataAccessSession,
        scored: ScoredSession | None = None,
        fset: BehavioralFeatureSet | None = None,
        observed_at_epoch_ms: float | None = None,
    ) -> ValidationOutcome:
        """Run the full ARDE review over one candidate finding."""
        ctx = ARDEContext(session=session, scored=scored, fset=fset, finding=finding)

        checks = self._consistency.run_checks(ctx)

        # --- exception system (always evaluated; records kept for ALL) ----
        exception_records: list[dict[str, Any]] = []
        if self._exceptions is not None:
            records = self._exceptions.evaluate(
                actor_id=session.actor_id,
                resources=session.resources_accessed,
                destinations=session.unique_destinations,
                bytes_total=(
                    session.bytes_accessed.value
                    if session.bytes_accessed is not None else None
                ),
                at_epoch_ms=observed_at_epoch_ms or finding.observed_at_epoch_ms,
            )
            exception_records = [r.model_dump(mode="json") for r in records]

        matched = [r for r in exception_records if r.get("matched")]

        # --- false-positive control: contextual reasoning ------------------
        fp_result = self._false_positive_control(session, scored, fset, matched)

        # --- status decision -------------------------------------------------
        status = self._decide_status(checks, matched, fp_result)

        # --- severity adjustment (downgrade-only) ----------------------------
        downgrade = self._severity_decision(finding, status, matched, fp_result, scored)

        # --- robustness -------------------------------------------------------
        robustness_score = self._robustness_score(checks, fset, session)
        robustness_level = self._robustness_level(robustness_score)

        outcome = ValidationOutcome(
            finding_id=finding.finding_id,
            session_id=finding.session_id,
            validation_status=status,
            robustness_score=robustness_score,
            robustness_level=robustness_level,
            checks=checks,
            exceptions_applied=exception_records,
            downgrade=downgrade,
        )

        if self._audit_log is not None:
            self._audit_log.record_validation(outcome, finding=finding)
        return outcome

    # ------------------------------------------------------------------
    # false-positive control: contextual reasoning
    # ------------------------------------------------------------------

    def _false_positive_control(
        self,
        session: DataAccessSession,
        scored: ScoredSession | None,
        fset: BehavioralFeatureSet | None,
        matched_exceptions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Contextual reasoning over 'is big actually bad?'.

        10 GB of backup -> potentially normal (volume alone, no
        corroboration, known actor+resource pattern -> not a finding).
        10 GB sensitive + unknown destination + unusual actor +
        unexpected time -> high concern (volume AND corroboration).

        Returns structured context consumed by status/severity logic.
        """
        volume = fset.volume_score.value if fset is not None and fset.volume_score else None
        object_dev = fset.object_count_score.value if fset is not None and fset.object_count_score else None
        request_dev = fset.request_rate_score.value if fset is not None and fset.request_rate_score else None
        volume_family = [v for v in (volume, object_dev, request_dev) if v is not None]
        volume_elevated = bool(volume_family) and max(volume_family) >= 0.5

        # corroborating non-volume signals
        corroboration: list[str] = []
        def _add(name: str, feat_value: float | None, floor: float) -> None:
            if feat_value is not None and feat_value >= floor:
                corroboration.append(name)

        if fset is not None:
            _add("destination_novelty", fset.destination_score.value if fset.destination_score else None, 0.4)
            _add("access_pattern", fset.access_pattern_score.value if fset.access_pattern_score else None, 0.5)
            _add("sensitivity", fset.sensitivity_score.value if fset.sensitivity_score else None, 0.55)
            _add("time_anomaly", fset.time_score.value if fset.time_score else None, 0.5)
            _add("actor_resource", fset.actor_resource_score.value if fset.actor_resource_score else None, 0.5)
            _add("egress", fset.egress_score.value if fset.egress_score else None, 0.5)

        fired_rules = scored.fired_rules if scored is not None else []
        non_volume_rules = [
            r for r in fired_rules
            if r not in ("volume_deviation_elevated",)
        ]

        outcome = {
            "volume_elevated": volume_elevated,
            "corroborating_signals": corroboration,
            "corroboration_count": len(set(corroboration)),
            "non_volume_rules_fired": non_volume_rules,
            "matched_exception": bool(matched_exceptions),
            "exception_kinds": [r.get("kind") for r in matched_exceptions],
        }

        # A large transfer with NO corroboration and NO fired non-volume
        # rules is the shape of legitimate bulk movement.
        outcome["bulk_transfer_shape"] = bool(
            volume_elevated
            and not corroboration
            and not non_volume_rules
        )
        return outcome

    # ------------------------------------------------------------------
    # status decision
    # ------------------------------------------------------------------

    def _decide_status(
        self,
        checks: list[ValidationCheckResult],
        matched_exceptions: list[dict[str, Any]],
        fp: dict[str, Any],
    ) -> ValidationStatus:
        failed = [c for c in checks if c.status is CheckStatus.FAILED]
        critical_failed = [c for c in failed if c.severity is CheckSeverity.CRITICAL]
        warnings = [c for c in checks if c.status is CheckStatus.WARNING]
        abstained = [c for c in checks if c.status is CheckStatus.ABSTAINED]
        decisive = [c for c in checks if c.status is not CheckStatus.ABSTAINED]

        # any critical failure (corrupted time, missing timestamps) -> reject
        if critical_failed:
            return ValidationStatus.REJECTED

        # model overreaction: the single-feature domination failure
        if any(c.check_name == "feature_consistency" for c in failed):
            return ValidationStatus.REVIEW_REQUIRED

        # two independent influencing failures -> the evidence does not
        # hold together; reject
        if len(failed) >= self._config.failed_check_for_reject:
            return ValidationStatus.REJECTED

        # legitimate-activity exception matched: never silent. The finding
        # stays visible but requires review (analyst or workflow decides).
        if matched_exceptions:
            return ValidationStatus.REVIEW_REQUIRED

        # bulk-transfer shape (big volume, zero corroboration): review,
        # not auto-pass — an analyst sees it once, the record is auditable.
        if fp.get("bulk_transfer_shape"):
            return ValidationStatus.REVIEW_REQUIRED

        if len(decisive) < self._config.checks_required_for_pass:
            # too many abstentions to pass cleanly
            if failed or warnings:
                return ValidationStatus.REVIEW_REQUIRED
            return ValidationStatus.PASSED_WITH_WARNINGS

        if warnings or abstained:
            return ValidationStatus.PASSED_WITH_WARNINGS
        return ValidationStatus.PASSED

    # ------------------------------------------------------------------
    # severity decision (downgrade-only, auditable)
    # ------------------------------------------------------------------

    def _severity_decision(
        self,
        finding: SecurityFinding,
        status: ValidationStatus,
        matched_exceptions: list[dict[str, Any]],
        fp: dict[str, Any],
        scored: ScoredSession | None,
    ) -> dict[str, Any] | None:
        """Downgrades only. REJECTED/REVIEW cap at MEDIUM; bulk-transfer
        shape with an exception caps at LOW. Never upgrades."""
        if finding.severity is None:
            return None

        original = finding.severity
        adjusted: FindingSeverity = original
        reason: str | None = None

        if status is ValidationStatus.REJECTED:
            adjusted = FindingSeverity.MEDIUM
            reason = "validation REJECTED: severity capped at medium pending review"
        elif status is ValidationStatus.REVIEW_REQUIRED:
            if fp.get("bulk_transfer_shape") and matched_exceptions:
                adjusted = FindingSeverity.LOW
                reason = (
                    "bulk-transfer shape with approved-activity exception: "
                    "capped at low, kept visible for audit"
                )
            elif fp.get("bulk_transfer_shape"):
                adjusted = FindingSeverity.MEDIUM
                reason = "bulk-transfer shape without corroboration: capped at medium for review"

        if adjusted is original:
            return None

        order = _SEVERITY_ORDER
        if order.index(adjusted) > order.index(original):
            # defense in depth: never upgrade
            return None

        return {
            "from": original.value,
            "to": adjusted.value,
            "reason": reason,
        }

    # ------------------------------------------------------------------
    # robustness
    # ------------------------------------------------------------------

    def _robustness_score(
        self,
        checks: list[ValidationCheckResult],
        fset: BehavioralFeatureSet | None,
        session: DataAccessSession,
    ) -> float:
        """0..1: how resilient the verdict is to missing/conflicting data.

        Start from the share of checks that ran decisively and passed;
        subtract for warnings/failures; add a small bonus for observed
        (not estimated) feature availability.
        """
        if not checks:
            return 0.0
        n = len(checks)
        passed = sum(1 for c in checks if c.status is CheckStatus.PASSED)
        warnings = sum(1 for c in checks if c.status is CheckStatus.WARNING)
        failed = sum(1 for c in checks if c.status is CheckStatus.FAILED)
        abstained = sum(1 for c in checks if c.status is CheckStatus.ABSTAINED)

        score = (passed / n) - 0.10 * warnings - 0.25 * failed
        if abstained == n:
            score = 0.0

        observed_bonus = 0.0
        if fset is not None:
            availability = fset.feature_availability or {}
            if availability:
                observed_share = sum(
                    1 for v in availability.values() if v == "observed"
                ) / len(availability)
                observed_bonus = self._config.robustness_observed_bonus * observed_share

        return round(max(0.0, min(1.0, score + observed_bonus)), 4)

    @staticmethod
    def _robustness_level(score: float) -> RobustnessLevel:
        if score >= 0.65:
            return RobustnessLevel.ROBUST
        if score >= 0.4:
            return RobustnessLevel.MODERATE
        return RobustnessLevel.FRAGILE
