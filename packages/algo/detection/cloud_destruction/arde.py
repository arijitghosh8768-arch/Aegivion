"""ARDE validation — **Part 6**.

ARDE (Audit, Review & Detection Evaluation) *challenges* every
candidate finding before it leaves the detector. It asks the
questions an analyst would ask:

- Could this be scheduled maintenance or lifecycle cleanup?
- Could the backup deletion be expected?
- Are the telemetry sources complete?
- Do the modification and deletion signals agree?
- Does the sequence make sense?
- Is the resource actually critical?
- Are recovery mechanisms still available?
- Does the ML model disagree with deterministic evidence?

It answers them with **ten validation checks**:

1. ``event_consistency``       — finding ↔ session ↔ telemetry agree
2. ``sequence_consistency``    — ordering + sequence-model signal
3. ``resource_consistency``    — attribution + criticality claims
4. ``time_consistency``        — timestamps bound the observation
5. ``baseline_consistency``    — baseline claims match its quality
6. ``recovery_consistency``    — recoverability claims match evidence
7. ``model_rule_agreement``    — ML vs deterministic rule signals
8. ``telemetry_completeness``  — how much evidence exists at all
9. ``protection_state_consistency`` — protection claims vs counters
10. ``feature_provenance_validation`` — every value traceable

Design rules:

- **ARDE never mutates a finding.** Risk, confidence and severity
  are exactly what the detector produced; validation only records
  verdicts. Challenges surface as ``WARN``/``FAIL`` verdicts and as
  contradicting evidence in the explainability layer.
- **ARDE never raises.** A check that cannot evaluate itself records
  ``FAIL`` with the internal error — a broken validator must never
  break detection.
- **Nothing is invented.** Every verdict cites the concrete values
  (or their absence) that produced it.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from detection.cloud_destruction.confidence import ConfidenceResult
from detection.cloud_destruction.features import SessionFeatureVector
from detection.cloud_destruction.finding import DestructionFinding
from detection.cloud_destruction.registry import ARDE_VERSION
from detection.cloud_destruction.schemas import (
    ActionCategory,
    BusinessCriticality,
    DestructiveActivitySession,
    ResourceActivityEvent,
)
from detection.cloud_destruction.scorer import DestructionRisk

__all__ = [
    "ArdeConfig",
    "ArdeValidator",
    "CheckVerdict",
    "ValidationCheck",
    "ValidationReport",
]


def _safe_attr(obj: Any, name: str) -> Optional[str]:
    """Read an identifier off an object that may be None."""
    if obj is None:
        return None
    return getattr(obj, name, None)


class CheckVerdict(str, Enum):
    """Outcome of one validation check."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class ArdeConfig(BaseModel):
    """Thresholds for the ten ARDE checks (all documented, tuned here)."""

    model_config = ConfigDict(frozen=True)

    version: str = ARDE_VERSION

    # check 8: telemetry completeness
    telemetry_pass_threshold: float = 0.75
    telemetry_warn_threshold: float = 0.45
    weight_feature_availability: float = 0.5
    weight_event_detail: float = 0.3
    weight_scored_evidence: float = 0.2

    # check 3: resource consistency
    unknown_resource_type_warn_share: float = 0.5

    # check 10: provenance
    require_provenance_method: bool = True


class ValidationCheck(BaseModel):
    """Verdict of one ARDE check, with the evidence behind it."""

    model_config = ConfigDict(frozen=True)

    check_id: str
    verdict: CheckVerdict
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    evidence: dict[str, Any] = Field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "verdict": self.verdict.value,
            "reasons": list(self.reasons),
            "evidence": self.evidence,
        }


class ValidationReport(BaseModel):
    """Complete ARDE challenge record for one finding."""

    model_config = ConfigDict(frozen=True)

    finding_id: Optional[str]
    session_id: Optional[str]
    validator_version: str = ARDE_VERSION
    overall: CheckVerdict
    checks: dict[str, ValidationCheck]
    failed_checks: tuple[str, ...] = Field(default_factory=tuple)
    warnings: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def challenged(self) -> bool:
        """True when ARDE raised any challenge (WARN or FAIL)."""
        return self.overall is not CheckVerdict.PASS

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "session_id": self.session_id,
            "validator_version": self.validator_version,
            "overall": self.overall.value,
            "checks": {k: v.to_log_dict() for k, v in self.checks.items()},
            "failed_checks": list(self.failed_checks),
            "warnings": list(self.warnings),
        }


class ArdeValidator:
    """Challenges candidate findings with the ten ARDE checks.

    Pure and side-effect free: validation reads the finding, the
    session, its feature vector, the fused risk/confidence and the
    session's telemetry, and returns a :class:`ValidationReport`.
    It never mutates any of its inputs.
    """

    def __init__(self, config: Optional[ArdeConfig] = None) -> None:
        self._config = config or ArdeConfig()

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #

    def validate(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent] = (),
    ) -> ValidationReport:
        """Run all ten checks; never raises."""
        checks: dict[str, ValidationCheck] = {}
        for check_id, runner in self._CHECKS:
            try:
                checks[check_id] = runner(
                    self, finding, session, vector, risk, confidence, events
                )
            except Exception as exc:  # noqa: BLE001 - validator must never break detection
                checks[check_id] = ValidationCheck(
                    check_id=check_id,
                    verdict=CheckVerdict.FAIL,
                    reasons=(f"check could not evaluate: {type(exc).__name__}: {exc}",),
                )

        failed = tuple(
            check_id for check_id, check in checks.items()
            if check.verdict is CheckVerdict.FAIL
        )
        warnings = tuple(
            f"{check_id}: {reason}"
            for check_id, check in checks.items()
            if check.verdict is CheckVerdict.WARN
            for reason in check.reasons
        )
        if failed:
            overall = CheckVerdict.FAIL
        elif warnings:
            overall = CheckVerdict.WARN
        else:
            overall = CheckVerdict.PASS

        return ValidationReport(
            finding_id=_safe_attr(finding, "finding_id"),
            session_id=_safe_attr(session, "session_id"),
            validator_version=self._config.version,
            overall=overall,
            checks=checks,
            failed_checks=failed,
            warnings=warnings,
        )

    # ------------------------------------------------------------------ #
    # The ten checks
    # ------------------------------------------------------------------ #

    def _check_event_consistency(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []
        evidence: dict[str, Any] = {
            "finding_event_count": len(finding.event_ids),
            "session_event_count": session.event_count,
        }

        if list(finding.event_ids) != list(session.event_ids):
            reasons.append(
                "finding records different events than its session "
                f"({len(finding.event_ids)} vs {session.event_count})"
            )
        if list(finding.resources_touched) != list(session.resources_touched):
            reasons.append("finding resource attribution differs from session")

        if events:
            evidence["telemetry_event_count"] = len(events)
            if len(events) != session.event_count:
                reasons.append(
                    "session aggregates "
                    f"{session.event_count} events but telemetry carries "
                    f"{len(events)} (duplicated or dropped events)"
                )
            seen: set[str] = set()
            duplicates = 0
            for event in events:
                if event.event_id in seen:
                    duplicates += 1
                seen.add(event.event_id)
            if duplicates:
                reasons.append(f"{duplicates} duplicated event_ids in telemetry")
            missing = [eid for eid in finding.event_ids if eid not in seen]
            if missing:
                reasons.append(
                    f"{len(missing)} finding events absent from telemetry"
                )
        else:
            reasons.append("no event detail provided — event consistency unverified")

        verdict = CheckVerdict.FAIL if reasons and events else (
            CheckVerdict.WARN if reasons else CheckVerdict.PASS
        )
        if reasons and not events:
            verdict = CheckVerdict.WARN
        return ValidationCheck(
            check_id="event_consistency",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    def _check_sequence_consistency(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []
        evidence: dict[str, Any] = {}

        if session.start_time is not None and session.end_time is not None:
            if session.start_time > session.end_time:
                reasons.append("session start_time is after end_time")
            evidence["duration_seconds"] = session.duration_seconds

        if events:
            ordered = all(
                events[i].timestamp <= events[i + 1].timestamp
                for i in range(len(events) - 1)
            )
            evidence["telemetry_in_chronological_order"] = ordered
            if not ordered:
                reasons.append(
                    "telemetry arrived out of chronological order "
                    "(session builder sorted it; counts unaffected)"
                )
            first = min(e.timestamp for e in events)
            last = max(e.timestamp for e in events)
            if session.start_time is not None and first != session.start_time:
                reasons.append("session start_time does not match earliest event")
            if session.end_time is not None and last != session.end_time:
                reasons.append("session end_time does not match latest event")

        sequence = vector.sequence_anomaly
        if sequence is None or not sequence.available:
            reasons.append(
                f"sequence signal unavailable "
                f"({(sequence.reason if sequence else 'no_feature')})"
            )
        elif sequence.value is not None and sequence.value > 0.5:
            evidence["sequence_anomaly"] = sequence.value

        contribution = (risk.contributions or {}).get("sequence")
        if contribution is not None and (sequence is None or not sequence.available):
            reasons.append(
                "sequence contribution present in fusion but sequence feature "
                "reports unavailable — inconsistent fusion"
            )

        verdict = CheckVerdict.FAIL if any(
            "does not match" in r or "inconsistent" in r or "after end_time" in r
            for r in reasons
        ) else (
            CheckVerdict.WARN if reasons else CheckVerdict.PASS
        )
        return ValidationCheck(
            check_id="sequence_consistency",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    def _check_resource_consistency(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []
        evidence: dict[str, Any] = {
            "destructive_event_count": session.destructive_event_count,
            "unique_resource_count": session.unique_resource_count,
        }

        if session.destructive_event_count > 0 and not session.resources_touched:
            reasons.append(
                "destructive activity without any resource attribution"
            )

        touched = {r for r in session.resources_touched if r}
        finding_resources = {r for r in finding.resources_touched if r}
        if not finding_resources.issubset(touched):
            reasons.append("finding attributes resources the session never touched")

        if events:
            unknown = sum(
                1 for e in events if e.resource_type.value == "unknown"
            )
            if unknown / len(events) > self._config.unknown_resource_type_warn_share:
                reasons.append(
                    f"{unknown}/{len(events)} events carry unknown resource types "
                    "(catalog enrichment missing)"
                )
            evidence["unknown_resource_type_events"] = unknown

        if events:
            critical_in_events = any(
                e.business_criticality is BusinessCriticality.CRITICAL for e in events
            )
            evidence["critical_in_events"] = critical_in_events
            if critical_in_events != session.critical_resource_touched:
                reasons.append(
                    "session critical-resource flag disagrees with event criticality"
                )
        elif session.critical_resource_touched:
            reasons.append(
                "critical resource claimed without event detail to verify"
            )

        verdict = CheckVerdict.FAIL if any(
            "without any resource attribution" in r
            or "never touched" in r
            or "disagrees" in r
            for r in reasons
        ) else (
            CheckVerdict.WARN if reasons else CheckVerdict.PASS
        )
        return ValidationCheck(
            check_id="resource_consistency",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    def _check_time_consistency(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []
        evidence: dict[str, Any] = {}

        if session.start_time is not None and session.end_time is not None:
            if session.end_time < session.start_time:
                reasons.append(
                    "negative session duration "
                    f"({session.duration_seconds:.0f}s clamped)"
                )

        if finding.observed_at is not None:
            evidence["observed_at"] = finding.observed_at.isoformat()
            if session.start_time is not None and finding.observed_at < session.start_time:
                reasons.append("finding observed_at precedes session start")
            if session.end_time is not None and finding.observed_at > session.end_time:
                reasons.append("finding observed_at follows session end")

        if events:
            earliest = min(e.timestamp for e in events)
            latest = max(e.timestamp for e in events)
            evidence["event_span_seconds"] = (latest - earliest).total_seconds()
            if session.start_time is not None and earliest < session.start_time:
                reasons.append("event timestamp precedes session start_time")
            if session.end_time is not None and latest > session.end_time:
                reasons.append("event timestamp follows session end_time")
        else:
            reasons.append("no event detail — time bounds unverified")

        verdict = CheckVerdict.FAIL if any(
            "precedes" in r or "follows" in r or "negative" in r for r in reasons
        ) else (
            CheckVerdict.WARN if reasons else CheckVerdict.PASS
        )
        return ValidationCheck(
            check_id="time_consistency",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    def _check_baseline_consistency(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []
        evidence: dict[str, Any] = {
            "baseline_quality": vector.baseline_quality.value,
            "baseline_version": vector.baseline_version,
        }

        quality = vector.baseline_quality.value
        if quality == "none":
            if vector.baseline_version is not None:
                reasons.append("baseline_version present but baseline quality is NONE")
        elif vector.baseline_version is None:
            reasons.append(
                f"baseline quality {quality} claimed without a baseline_version"
            )

        # Baseline-*relative* features (deviations, ratio/scope
        # anomalies) may only claim a measurement when a baseline
        # exists; a NONE baseline must leave them unavailable. An
        # INSUFFICIENT baseline yields weak (but real) evidence.
        # Count-based anomaly scores (snapshot/backup/version)
        # are absolute heuristics and are legitimately available
        # without any baseline.
        baseline_relative = (
            "write_rate_deviation",
            "modify_rate_deviation",
            "rewrite_rate_deviation",
            "resource_scope_deviation",
            "object_count_deviation",
            "delete_rate_deviation",
            "delete_ratio_anomaly",
            "deletion_scope_anomaly",
        )
        for name in baseline_relative:
            value = getattr(vector, name, None)
            if value is None or not value.available:
                continue
            if quality == "none":
                reasons.append(
                    f"{name} measured without any baseline"
                )
            elif quality == "insufficient":
                reasons.append(
                    f"{name} measured against an insufficient baseline"
                )

        contamination = vector.baseline_contamination or {}
        if contamination and vector.baseline_excluded_sessions is None:
            reasons.append(
                "baseline contamination recorded without exclusion counts"
            )
        evidence["baseline_contamination"] = dict(contamination)

        for name, provenance in (vector.feature_provenance or {}).items():
            if provenance.baseline_version is not None and (
                vector.baseline_version is not None
                and provenance.baseline_version != vector.baseline_version
            ):
                reasons.append(
                    f"{name} provenance references a different baseline version"
                )
                break

        verdict = CheckVerdict.FAIL if any(
            "claimed without" in r
            or "measured without any baseline" in r
            or "present but" in r
            for r in reasons
        ) else (
            CheckVerdict.WARN if reasons else CheckVerdict.PASS
        )
        return ValidationCheck(
            check_id="baseline_consistency",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    def _check_recovery_consistency(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []
        recovery_impairing = (
            session.snapshot_deletions + session.backup_deletions
        )
        evidence: dict[str, Any] = {
            "snapshot_deletions": session.snapshot_deletions,
            "backup_deletions": session.backup_deletions,
            "recovery_impairing_events": recovery_impairing,
        }

        recoverability = vector.recoverability
        if recoverability is not None and recoverability.available:
            evidence["recoverability"] = recoverability.value
            if recoverability.value is not None:
                if recoverability.value < 0.5 and recovery_impairing == 0:
                    reasons.append(
                        "low recoverability claimed without any recovery-impairing event"
                    )
                if recoverability.value >= 0.8 and recovery_impairing > 0:
                    reasons.append(
                        "high recoverability claimed while recovery mechanisms "
                        "were deleted"
                    )
        elif recovery_impairing > 0:
            reasons.append(
                "recovery mechanisms destroyed but recoverability unmeasured "
                f"({recoverability.reason if recoverability else 'no_feature'})"
            )

        destruction = vector.recovery_destruction
        if recovery_impairing > 0 and (
            destruction is None or not destruction.available
        ):
            reasons.append(
                "recovery-impairing deletions present but recovery_destruction "
                "feature unavailable"
            )

        verdict = CheckVerdict.FAIL if any(
            "without any recovery-impairing" in r or "claimed while" in r for r in reasons
        ) else (
            CheckVerdict.WARN if reasons else CheckVerdict.PASS
        )
        return ValidationCheck(
            check_id="recovery_consistency",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    def _check_model_rule_agreement(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []
        evidence: dict[str, Any] = {"model_agreement": risk.model_agreement}

        if risk.model_agreement is None:
            reasons.append("model-rule agreement unmeasured (no ML anomaly signal)")
        elif risk.model_agreement is False:
            reasons.append(
                "ML anomaly model disagrees with deterministic behavioral rules"
            )

        contributions = risk.contributions or {}
        if contributions.get("ml_anomaly") is not None:
            evidence["ml_anomaly_contribution"] = contributions["ml_anomaly"]
        behavioral = [
            name
            for name in ("delete", "delete_ratio", "version", "snapshot", "backup")
            if contributions.get(name) is not None
        ]
        evidence["behavioral_contributions"] = behavioral

        verdict = CheckVerdict.WARN if reasons else CheckVerdict.PASS
        return ValidationCheck(
            check_id="model_rule_agreement",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    def _check_telemetry_completeness(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []

        feature_names = getattr(vector, "_FEATURE_NAMES", ())
        available = len(vector.available_features)
        feature_share = available / len(feature_names) if feature_names else 0.0
        event_detail = 1.0 if events else 0.0
        contributions = risk.contributions or {}
        scored = [v for v in contributions.values() if v is not None]
        evidence_share = len(scored) / len(contributions) if contributions else 0.0

        cfg = self._config
        completeness = (
            feature_share * cfg.weight_feature_availability
            + event_detail * cfg.weight_event_detail
            + evidence_share * cfg.weight_scored_evidence
        ) / (
            cfg.weight_feature_availability
            + cfg.weight_event_detail
            + cfg.weight_scored_evidence
        )

        evidence: dict[str, Any] = {
            "available_features": available,
            "total_features": len(feature_names),
            "feature_availability_share": round(feature_share, 4),
            "has_event_detail": bool(events),
            "scored_evidence_share": round(evidence_share, 4),
            "completeness_score": round(completeness, 4),
            "missing_evidence": list(finding.missing_evidence),
        }

        if completeness < cfg.telemetry_warn_threshold:
            reasons.append(
                f"telemetry completeness {completeness:.2f} below warn threshold "
                f"{cfg.telemetry_warn_threshold}"
            )
        elif completeness < cfg.telemetry_pass_threshold:
            reasons.append(
                f"telemetry completeness {completeness:.2f} below pass threshold "
                f"{cfg.telemetry_pass_threshold}"
            )

        verdict = (
            CheckVerdict.FAIL
            if completeness < cfg.telemetry_warn_threshold
            else (
                CheckVerdict.WARN
                if completeness < cfg.telemetry_pass_threshold
                else CheckVerdict.PASS
            )
        )
        return ValidationCheck(
            check_id="telemetry_completeness",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    def _check_protection_state_consistency(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []
        evidence: dict[str, Any] = {
            "protection_changes": session.protection_changes,
        }

        degradation = vector.protection_degradation
        if session.protection_changes > 0 and (
            degradation is None or not degradation.available
        ):
            reasons.append(
                "protection changes observed but protection_degradation unavailable"
            )
        if degradation is not None and degradation.available and degradation.value:
            evidence["protection_degradation"] = degradation.value
            if degradation.value > 0 and session.protection_changes == 0:
                reasons.append(
                    "protection degradation claimed without any protection-change event"
                )

        if events:
            protected_snapshots = sum(
                1
                for e in events
                if e.action_category is ActionCategory.SNAPSHOT_DELETE
                and e.snapshot_protection_enabled
            )
            protected_backups = sum(
                1
                for e in events
                if e.action_category
                in (ActionCategory.BACKUP_DELETE, ActionCategory.RECOVERY_POINT_DELETE)
                and (e.backup_enabled or e.object_lock_enabled or e.versioning_enabled)
            )
            evidence["protected_snapshot_deletions"] = protected_snapshots
            evidence["protected_backup_deletions"] = protected_backups
            if protected_snapshots > session.snapshot_deletions:
                reasons.append("protected snapshot deletions exceed total snapshot deletions")
            if protected_backups > session.backup_deletions:
                reasons.append("protected backup deletions exceed total backup deletions")

        verdict = CheckVerdict.FAIL if any(
            "exceed" in r or "without any protection-change" in r for r in reasons
        ) else (
            CheckVerdict.WARN if reasons else CheckVerdict.PASS
        )
        return ValidationCheck(
            check_id="protection_state_consistency",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    def _check_feature_provenance_validation(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        vector: SessionFeatureVector,
        risk: DestructionRisk,
        confidence: ConfidenceResult,
        events: Sequence[ResourceActivityEvent],
    ) -> ValidationCheck:
        reasons: list[str] = []
        evidence: dict[str, Any] = {
            "features_with_provenance": len(vector.feature_provenance or {}),
        }

        for name in vector.feature_availability or ():
            if name not in (vector.feature_provenance or {}):
                reasons.append(f"{name} carries no provenance record")

        for name in getattr(vector, "_FEATURE_NAMES", ()):
            value = getattr(vector, name, None)
            if value is None:
                continue
            if value.available and value.value is None:
                reasons.append(f"{name} available but carries no value")
            if not value.available and value.value is not None:
                reasons.append(f"{name} unavailable but carries a value")
            provenance = (vector.feature_provenance or {}).get(name)
            if value.available and provenance is not None:
                if self._config.require_provenance_method and not provenance.method:
                    reasons.append(f"{name} measured without a recorded method")

        verdict = CheckVerdict.FAIL if any(
            "no provenance record" in r or "but carries" in r for r in reasons
        ) else (
            CheckVerdict.WARN if reasons else CheckVerdict.PASS
        )
        return ValidationCheck(
            check_id="feature_provenance_validation",
            verdict=verdict,
            reasons=tuple(reasons),
            evidence=evidence,
        )

    _CHECKS = (
        ("event_consistency", _check_event_consistency),
        ("sequence_consistency", _check_sequence_consistency),
        ("resource_consistency", _check_resource_consistency),
        ("time_consistency", _check_time_consistency),
        ("baseline_consistency", _check_baseline_consistency),
        ("recovery_consistency", _check_recovery_consistency),
        ("model_rule_agreement", _check_model_rule_agreement),
        ("telemetry_completeness", _check_telemetry_completeness),
        ("protection_state_consistency", _check_protection_state_consistency),
        ("feature_provenance_validation", _check_feature_provenance_validation),
    )
