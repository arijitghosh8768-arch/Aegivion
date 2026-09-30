"""Integration: attach ARDE validation + explanation to findings.

One call point used by the detector and by downstream consumers that
score findings outside the pipeline. Behavior:

- runs the validator (checks + exceptions + FP control + audit),
- builds the machine-readable explanation,
- attaches both under ``finding.metadata`` (``arde_validation``,
  ``arde_explanation``),
- applies the downgrade (if any) to the finding severity — an audited,
  reversible decision recorded on the finding itself; nothing is
  deleted, nothing is suppressed silently.
"""

from __future__ import annotations

from typing import Any

from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import BehavioralFeatureSet
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoredSession
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession, FindingSeverity, SecurityFinding

from .audit import AuditLog
from .explain import ExplainabilityBuilder, FindingExplanation
from .models import ValidationOutcome
from .validator import ARDEValidator


def validate_and_attach(
    finding: SecurityFinding,
    *,
    session: DataAccessSession,
    scored: ScoredSession | None = None,
    fset: BehavioralFeatureSet | None = None,
    validator: ARDEValidator | None = None,
    explainer: ExplainabilityBuilder | None = None,
    audit_log: AuditLog | None = None,
) -> ValidationOutcome:
    """Validate one finding and attach outcome + explanation to it."""
    validator = validator or ARDEValidator(audit_log=audit_log)
    explainer = explainer or ExplainabilityBuilder()

    outcome = validator.validate(
        finding,
        session=session,
        scored=scored,
        fset=fset,
        observed_at_epoch_ms=finding.observed_at_epoch_ms,
    )
    explanation = explainer.build(
        finding,
        session=session,
        scored=scored,
        fset=fset,
        outcome=outcome,
    )

    finding.metadata["arde_validation"] = outcome.model_dump(mode="json")
    finding.metadata["arde_explanation"] = explanation.model_dump(mode="json")

    if outcome.downgrade is not None:
        finding.severity = FindingSeverity(outcome.downgrade["to"])
        finding.metadata["arde_validation"]["downgrade_applied"] = True

    # Rebuild the stable output contract now that validation and the
    # behavioral feature set are known: severity/robustness and the
    # contradicting-evidence side become complete.
    from algo.data_exfiltration.data_exfiltration.output_contract import attach_output_contract

    attach_output_contract(
        finding, session=session, scored=scored, fset=fset, arde=outcome
    )

    return outcome


def explanation_of(finding: SecurityFinding) -> FindingExplanation | None:
    """Retrieve the attached explanation (typed) from a finding."""
    payload = finding.metadata.get("arde_explanation")
    if payload is None:
        return None
    return FindingExplanation.model_validate(payload)


def outcome_of(finding: SecurityFinding) -> ValidationOutcome | None:
    """Retrieve the attached validation outcome (typed) from a finding."""
    payload = finding.metadata.get("arde_validation")
    if payload is None:
        return None
    return ValidationOutcome.model_validate(payload)


def report_of(finding: SecurityFinding, **kwargs: Any) -> str | None:
    """Render the analyst-readable report from an attached explanation."""
    from .formatter import format_finding_report

    explanation = explanation_of(finding)
    if explanation is None:
        return None
    return format_finding_report(explanation, finding=finding, **kwargs)
