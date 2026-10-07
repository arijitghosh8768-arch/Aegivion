"""Destructive-behavior categorization & explainability — **Part 6**.

Two responsibilities, both strictly derived from detector output:

1. **Categorization** — :func:`categorize` classifies a session
   into the spec's destructive-behavior categories
   (:class:`DestructiveBehaviorCategory`). The detector never
   forces a case into "ransomware": findings are labeled
   ``"Potential cloud destructive activity"`` (:data:`FINDING_LABEL`)
   and carry one or more neutral categories.

2. **Explainability** — :class:`Explanation` is the
   machine-readable analyst package. It answers, with detector
   evidence only:

   - WHAT happened? (``what_happened``)
   - WHICH resources were affected? (``resources_affected``)
   - HOW unusual was it? (``how_unusual``)
   - What was normal? (``what_was_normal``)
   - What changed? (``what_changed``)
   - Which recovery mechanisms were affected?
     (``recovery_mechanisms_affected``)
   - Which signals contributed? (``signals_contributed``)
   - Which signals contradicted? (``signals_contradicted``)
   - What telemetry was missing? (``telemetry_missing``)

   plus the compact spec block: ``top_contributors``,
   ``supporting_evidence``, ``contradicting_evidence``,
   ``baseline_quality``, ``telemetry_completeness``,
   ``model_agreement``.

**The later Aegivion LLM layer may render this in natural
language but must never create evidence the detector did not
provide** — every string in an :class:`Explanation` is
computed here from measured values, counters and validation
verdicts. Nothing is invented: unavailable features are
reported as missing, never filled in.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from detection.cloud_destruction.arde import (
    ArdeConfig,
    CheckVerdict,
    ValidationReport,
)
from detection.cloud_destruction.confidence import ConfidenceResult
from detection.cloud_destruction.features import SessionFeatureVector
from detection.cloud_destruction.finding import DestructionFinding, Severity
from detection.cloud_destruction.provenance import MeasuredValue
from detection.cloud_destruction.registry import EXPLANATION_VERSION
from detection.cloud_destruction.schemas import DestructiveActivitySession
from detection.cloud_destruction.scorer import (
    DestructionRisk,
    _criticality_strength,
)

__all__ = [
    "DestructiveBehaviorCategory",
    "Explanation",
    "FINDING_LABEL",
    "build_explanation",
    "categorize",
    "telemetry_completeness_level",
]

#: Neutral finding label — the detector never claims ransomware.
FINDING_LABEL = "Potential cloud destructive activity"


class DestructiveBehaviorCategory(str, Enum):
    """Destructive-behavior categories (spec vocabulary).

    Categories describe *what kind* of destructive behavior was
    observed. They are neutral: no category asserts intent, and
    none of them is "ransomware".
    """

    MASS_MODIFICATION = "MASS_MODIFICATION"
    MASS_DELETION = "MASS_DELETION"
    VERSION_DESTRUCTION = "VERSION_DESTRUCTION"
    RECOVERY_DESTRUCTION = "RECOVERY_DESTRUCTION"
    PROTECTION_DEGRADATION = "PROTECTION_DEGRADATION"
    MASS_REWRITE = "MASS_REWRITE"
    MULTI_RESOURCE_DESTRUCTION = "MULTI_RESOURCE_DESTRUCTION"
    COMPOUND_DESTRUCTIVE_ACTIVITY = "COMPOUND_DESTRUCTIVE_ACTIVITY"


#: Documented categorization thresholds (session counters).
CATEGORY_THRESHOLDS: dict[str, int] = {
    "mass_modification": 5,
    "mass_deletion": 5,
    "mass_rewrite": 5,
    "multi_resource": 3,
}


def _truthy(value: Optional[MeasuredValue]) -> bool:
    return bool(
        value is not None
        and value.available
        and value.value is not None
        and value.value > 0
    )


def _value(value: Optional[MeasuredValue]) -> Optional[float]:
    """Unwrap a :class:`MeasuredValue` or accept a plain scalar.

    Some vector fields (e.g. ``business_criticality``) are plain
    catalog values rather than measured features, so an absent
    ``available`` flag must not be treated as unavailable.
    """
    if value is None:
        return None
    if not getattr(value, "available", True):
        return None
    raw = getattr(value, "value", value)
    return raw if isinstance(raw, (int, float)) else None


def categorize(
    session: DestructiveActivitySession,
    vector: SessionFeatureVector,
) -> tuple[DestructiveBehaviorCategory, ...]:
    """Classify a session into behavior categories.

    Pure function of session counters + feature availability.
    ``COMPOUND_DESTRUCTIVE_ACTIVITY`` is appended when two or
    more distinct categories co-occur.
    """
    categories: list[DestructiveBehaviorCategory] = []

    modified_count = len(session.modified_resources)
    deleted_count = len(session.deleted_resources)

    if modified_count >= CATEGORY_THRESHOLDS["mass_modification"]:
        categories.append(DestructiveBehaviorCategory.MASS_MODIFICATION)

    if (
        deleted_count >= CATEGORY_THRESHOLDS["mass_deletion"]
        or (
            session.destructive_event_count >= 10
            and deleted_count >= 1
        )
    ):
        categories.append(DestructiveBehaviorCategory.MASS_DELETION)

    version_dominant = _value(vector.version_deletion_ratio)
    if session.version_deletions >= 1 and (
        session.version_deletions >= CATEGORY_THRESHOLDS["mass_deletion"]
        or (version_dominant is not None and version_dominant >= 0.5)
    ):
        categories.append(DestructiveBehaviorCategory.VERSION_DESTRUCTION)

    if (
        session.snapshot_deletions + session.backup_deletions >= 1
        or _truthy(vector.recovery_destruction)
    ):
        categories.append(DestructiveBehaviorCategory.RECOVERY_DESTRUCTION)

    if session.protection_changes >= 1 or _truthy(vector.protection_degradation):
        categories.append(DestructiveBehaviorCategory.PROTECTION_DEGRADATION)

    if (
        session.rewrite_count >= CATEGORY_THRESHOLDS["mass_rewrite"]
        or _truthy(vector.rewrite_transform)
    ):
        categories.append(DestructiveBehaviorCategory.MASS_REWRITE)

    if (
        session.unique_resource_count >= CATEGORY_THRESHOLDS["multi_resource"]
        and session.destructive_event_count
        >= CATEGORY_THRESHOLDS["multi_resource"]
    ):
        categories.append(DestructiveBehaviorCategory.MULTI_RESOURCE_DESTRUCTION)

    if len(categories) >= 2:
        categories.append(
            DestructiveBehaviorCategory.COMPOUND_DESTRUCTIVE_ACTIVITY
        )

    return tuple(categories)


# ---------------------------------------------------------------------- #
# Contributor phrasing — every string is computed from a measured value
# ---------------------------------------------------------------------- #

#: contribution key -> (feature name, phrase formatter)
def _describe_contributor(
    key: str,
    contribution: float,
    vector: SessionFeatureVector,
    *,
    sequence_score: Optional[float] = None,
) -> Optional[str]:
    """Render one contribution as an evidence-backed phrase."""
    feature = {
        "delete": "delete_rate_deviation",
        "delete_ratio": "delete_ratio_anomaly",
        "modify": "modify_rate_deviation",
        "version": "version_delete_anomaly",
        "snapshot": "snapshot_delete_anomaly",
        "backup": "backup_delete_anomaly",
        "protection": "protection_degradation",
        "rewrite": "rewrite_transform",
        "scope": "resource_scope_deviation",
        "temporal": "temporal",
        "recoverability": "recoverability",
    }.get(key)

    if key == "criticality":
        strength = _criticality_strength(vector.business_criticality)
        if strength is None:
            return None
        return f"Business-critical resource targeted (strength {strength:.2f})"

    if key == "ml_anomaly":
        return f"ML anomaly model flagged the session (weighted {contribution:.3f})"

    if key == "supervised":
        return f"Supervised model probability pulls risk (weighted {contribution:.3f})"

    if feature is None:
        return None

    if key == "sequence":
        if sequence_score is None:
            return None
        return (
            "Unusual action sequence "
            f"(sequence-model score {sequence_score:.2f})"
        )

    measured = getattr(vector, feature, None)
    if not isinstance(measured, MeasuredValue) or not measured.available:
        return None
    value = measured.value
    if value is None:
        return None

    if key == "delete":
        return f"Delete rate {value:.1f}x baseline"
    if key == "delete_ratio":
        return f"Deletion ratio anomaly {value:.2f} (share of events that delete)"
    if key == "modify":
        return f"Modify rate {value:.1f}x baseline"
    if key == "version":
        return f"Mass version deletion (anomaly {value:.2f})"
    if key == "snapshot":
        return f"Snapshot deletion anomaly {value:.2f}"
    if key == "backup":
        return f"Recovery-point deletion anomaly {value:.2f}"
    if key == "protection":
        return f"Protection-state degradation (score {value:.2f})"
    if key == "rewrite":
        return f"Unusual rewrite sequence ({value:.0%} of writes rewritten)"
    if key == "scope":
        return f"Resource scope {value:.1f}x baseline"
    if key == "temporal":
        return f"Off-hours / unusual timing pattern (score {value:.2f})"
    if key == "sequence":
        return (
            "Unusual action sequence "
            f"(sequence-model score {value:.2f})"
        )
    if key == "recoverability":
        return f"Recovery mechanisms impaired (recoverability {value:.2f})"
    return None


def _supporting_evidence(
    session: DestructiveActivitySession,
    vector: SessionFeatureVector,
    risk: DestructionRisk,
) -> list[str]:
    """Evidence that supports the finding (never invented)."""
    support: list[str] = []

    if session.destructive_event_count:
        support.append(
            f"{session.destructive_event_count} destructive events in session"
        )
    if session.deleted_resources:
        support.append(
            f"{len(session.deleted_resources)} resources deleted"
        )
    if session.modified_resources:
        support.append(
            f"{len(session.modified_resources)} resources modified"
        )
    if session.version_deletions:
        support.append(f"{session.version_deletions} object versions deleted")
    if session.delete_marker_count:
        support.append(
            f"{session.delete_marker_count} delete markers created"
        )
    if session.snapshot_deletions:
        support.append(f"{session.snapshot_deletions} snapshots deleted")
    if session.backup_deletions:
        support.append(
            f"{session.backup_deletions} backups/recovery points deleted"
        )
    if session.protection_changes:
        support.append(f"{session.protection_changes} protection changes")
    if session.restore_count == 0 and (
        session.snapshot_deletions + session.backup_deletions
    ) >= 1:
        support.append("no restore activity observed in the session")

    if risk.boosts_applied:
        support.append(
            "policy boosts applied: " + ", ".join(risk.boosts_applied)
        )
    if session.critical_resource_touched:
        support.append("business-critical resources among those touched")
    return support


def telemetry_completeness_level(score: float) -> str:
    """Map a completeness score to the spec's vocabulary."""
    cfg = ArdeConfig()
    if score >= cfg.telemetry_pass_threshold:
        return "HIGH"
    if score >= cfg.telemetry_warn_threshold:
        return "MODERATE"
    return "LOW"


class Explanation(BaseModel):
    """Machine-readable explanation for one finding.

    The ``to_dict()`` block matches the spec's example shape
    (``top_contributors`` / ``supporting_evidence`` /
    ``contradicting_evidence`` / ``baseline_quality`` /
    ``telemetry_completeness`` / ``model_agreement``) and adds
    the full analyst Q&A block. Every field is derived from
    detector output — an LLM may rephrase, never fabricate.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str
    session_id: str
    explanation_version: str = EXPLANATION_VERSION
    label: str = FINDING_LABEL
    categories: tuple[str, ...] = Field(default_factory=tuple)

    # compact spec block
    top_contributors: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    baseline_quality: str
    telemetry_completeness: str
    model_agreement: str

    # analyst Q&A block
    what_happened: str = ""
    resources_affected: list[str] = Field(default_factory=list)
    how_unusual: str = ""
    what_was_normal: str = ""
    what_changed: str = ""
    recovery_mechanisms_affected: list[str] = Field(default_factory=list)
    signals_contributed: list[str] = Field(default_factory=list)
    signals_contradicted: list[str] = Field(default_factory=list)
    telemetry_missing: list[str] = Field(default_factory=list)

    # numeric context (exactly what the detector measured)
    risk_score: float
    confidence_score: float
    severity: str

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def build_explanation(
    finding: DestructionFinding,
    session: DestructiveActivitySession,
    vector: SessionFeatureVector,
    risk: DestructionRisk,
    confidence: ConfidenceResult,
    events: Sequence[Any] = (),
    report: Optional[ValidationReport] = None,
    recognized_patterns: Sequence[str] = (),
    sequence_score: Optional[float] = None,
) -> Explanation:
    """Build the machine-readable explanation for one finding.

    Pure: reads detector outputs (and optionally the ARDE
    report and recognized legitimate patterns) and computes
    every field. Raises nothing for missing data — gaps are
    reported in ``telemetry_missing``.
    """
    contributions = risk.contributions or {}
    scored = [
        (key, value)
        for key, value in contributions.items()
        if value is not None
        and value > 0
        and not key.endswith("_fallback")
    ]
    scored.sort(key=lambda item: abs(item[1]), reverse=True)

    top_contributors: list[str] = []
    for key, value in scored:
        if len(top_contributors) >= 5:
            break
        phrase = _describe_contributor(
            key,
            value,
            vector,
            sequence_score=sequence_score,
        )
        if phrase:
            top_contributors.append(phrase)

    supporting = _supporting_evidence(session, vector, risk)

    contradicting: list[str] = []
    contradicted_signals: list[str] = []
    if risk.model_agreement is False:
        contradicting.append(
            "ML anomaly model disagrees with the deterministic "
            "behavioral rules"
        )
        contradicted_signals.append("model_rule_agreement")
    if report is not None:
        for check_id, check in report.checks.items():
            if check.verdict is CheckVerdict.FAIL:
                contradicting.append(
                    f"ARDE {check_id} FAILED: "
                    + ("; ".join(check.reasons) or "no reasons recorded")
                )
            elif check.verdict is CheckVerdict.WARN:
                for reason in check.reasons:
                    contradicting.append(f"ARDE {check_id} warning: {reason}")
        if report.failed_checks:
            contradicted_signals.extend(report.failed_checks)
    approved = finding.approved_activity or {}
    if approved.get("approved"):
        contradicting.append(
            "declared legitimate activity matched: "
            + str(approved.get("justification") or "")
        )
    for pattern in recognized_patterns:
        contradicting.append(f"telemetry consistent with legitimate pattern: {pattern}")

    quality = vector.baseline_quality.value
    if quality in ("none", "insufficient"):
        contradicting.append(
            f"deviation signals measured against a {quality} baseline — "
            "baseline-relative evidence is weak"
        )
    recoverability = _value(vector.recoverability)
    if recoverability is not None and recoverability >= 0.8:
        contradicting.append(
            f"recovery mechanisms still available (recoverability "
            f"{recoverability:.2f})"
        )

    # telemetry completeness: prefer the ARDE measurement
    completeness_score: Optional[float] = None
    if report is not None:
        completeness_score = (
            report.checks.get("telemetry_completeness")
            .evidence.get("completeness_score")
            if report.checks.get("telemetry_completeness")
            else None
        )
    if completeness_score is None:
        names = getattr(vector, "_FEATURE_NAMES", ())
        completeness_score = (
            len(vector.available_features) / len(names) if names else 0.0
        )

    categories = tuple(c.value for c in categorize(session, vector))

    # --- analyst Q&A --------------------------------------------------- #
    destructive_kinds: list[str] = []
    if session.deleted_resources:
        destructive_kinds.append("deletions")
    if session.modified_resources:
        destructive_kinds.append("modifications")
    if session.version_deletions:
        destructive_kinds.append("version deletions")
    if session.snapshot_deletions or session.backup_deletions:
        destructive_kinds.append("recovery-point deletions")
    if session.protection_changes:
        destructive_kinds.append("protection changes")
    if session.rewrite_count:
        destructive_kinds.append("rewrites")
    what_happened = (
        f"{session.destructive_event_count} destructive events "
        f"({', '.join(destructive_kinds) or 'no destructive events'}) "
        f"by actor {session.actor_id or 'unknown'} in account "
        f"{session.account_id or 'unknown'}; categorized as "
        + (", ".join(categories) if categories else "no destructive category")
    )

    unusual_parts: list[str] = []
    for phrase in top_contributors[:3]:
        unusual_parts.append(phrase.lower())
    how_unusual = (
        "; ".join(unusual_parts)
        if unusual_parts
        else "behavior within normal bounds — low anomaly across all measured signals"
    )

    if quality == "good":
        what_was_normal = (
            f"actor's own baseline (version {vector.baseline_version or 'n/a'}, "
            "quality GOOD)"
        )
    elif quality == "limited":
        what_was_normal = (
            f"partial baseline (version {vector.baseline_version or 'n/a'}, "
            "quality LIMITED — limited history)"
        )
    elif quality == "insufficient":
        what_was_normal = (
            f"insufficient baseline (version {vector.baseline_version or 'n/a'}) — "
            "too little trusted history"
        )
    else:
        what_was_normal = "no baseline — this actor has no trusted history"

    what_changed = (
        "; ".join(top_contributors[:2])
        if top_contributors
        else "nothing measured changed significantly"
    )

    recovery_mechanisms: list[str] = []
    if session.version_deletions or session.delete_marker_count:
        recovery_mechanisms.append(
            f"object versioning ({session.version_deletions} versions, "
            f"{session.delete_marker_count} delete markers)"
        )
    if session.snapshot_deletions:
        recovery_mechanisms.append(
            f"snapshots ({session.snapshot_deletions} deleted)"
        )
    if session.backup_deletions:
        recovery_mechanisms.append(
            f"backups/recovery points ({session.backup_deletions} deleted)"
        )
    if session.protection_changes:
        recovery_mechanisms.append(
            f"protection state ({session.protection_changes} changes)"
        )

    telemetry_missing = list(finding.missing_evidence)
    for name in getattr(vector, "_FEATURE_NAMES", ()):
        measured = getattr(vector, name, None)
        if isinstance(measured, MeasuredValue) and not measured.available:
            telemetry_missing.append(f"{name}: {measured.reason or 'unavailable'}")

    signals_contributed = [key for key, _ in scored]

    return Explanation(
        finding_id=finding.finding_id,
        session_id=session.session_id,
        categories=categories,
        top_contributors=top_contributors,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        baseline_quality=quality.upper(),
        telemetry_completeness=telemetry_completeness_level(completeness_score),
        model_agreement={
            True: "STRONG",
            False: "WEAK",
            None: "UNKNOWN",
        }[risk.model_agreement],
        what_happened=what_happened,
        resources_affected=sorted({r for r in session.resources_touched if r}),
        how_unusual=how_unusual,
        what_was_normal=what_was_normal,
        what_changed=what_changed,
        recovery_mechanisms_affected=recovery_mechanisms,
        signals_contributed=signals_contributed,
        signals_contradicted=contradicted_signals,
        telemetry_missing=telemetry_missing,
        risk_score=risk.risk_score,
        confidence_score=confidence.confidence_score,
        severity=finding.severity.value,
    )
