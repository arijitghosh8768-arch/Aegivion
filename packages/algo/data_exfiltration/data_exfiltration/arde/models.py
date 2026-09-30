"""ARDE result models: validation status, checks, robustness.

Every output is data: statuses are enums, checks carry their own
evidence, and nothing here mutates the finding under review.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

ARDE_VALIDATION_VERSION = "arde-validation-1.0.0"


class ValidationStatus(str, Enum):
    """Outcome of ARDE review over one finding.

    PASSED                - evidence supports the finding as emitted.
    PASSED_WITH_WARNINGS  - finding stands, but noted weaknesses (gaps,
                            partial conflicts) travel with it.
    REVIEW_REQUIRED       - evidence is mixed, thin, or a legitimate-
                            activity exception is in play: an analyst
                            (or the exception registry) must decide.
    REJECTED              - the finding does not survive scrutiny
                            (internally inconsistent evidence, model
                            overreaction to a single feature, or a
                            scoped exception that fully explains it).
    """

    PASSED = "PASSED"
    PASSED_WITH_WARNINGS = "PASSED_WITH_WARNINGS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REJECTED = "REJECTED"


class CheckStatus(str, Enum):
    """Per-check outcome. ABSTAINED means the check could not run
    (telemetry absent) — an abstention is evidence of incompleteness,
    not innocence."""

    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    ABSTAINED = "abstained"


class CheckSeverity(str, Enum):
    """How much a failing check matters. ``influence`` records how hard
    the check pushes the final status when it fails."""

    INFORMATIONAL = "informational"
    INFLUENCING = "influencing"
    CRITICAL = "critical"


class RobustnessLevel(str, Enum):
    """How much the verdict depends on fragile evidence.

    ROBUST       - multiple independent, complete signals agree.
    MODERATE     - some evidence is estimated/partial but corroborated.
    FRAGILE      - verdict rests on thin, conflicting, or missing data.
    """

    ROBUST = "ROBUST"
    MODERATE = "MODERATE"
    FRAGILE = "FRAGILE"


class ValidationCheckResult(BaseModel):
    """One named consistency check over one finding."""

    check_name: str
    status: CheckStatus = CheckStatus.ABSTAINED
    severity: CheckSeverity = CheckSeverity.INFLUENCING
    message: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    """Machine-readable evidence for this check (feeds explanations)."""


class ValidationOutcome(BaseModel):
    """Complete ARDE review result for one finding."""

    finding_id: str
    session_id: str | None = None
    validation_status: ValidationStatus = ValidationStatus.REVIEW_REQUIRED
    robustness_score: float = 0.0
    """0..1: how resilient the finding is to missing/conflicting data."""
    robustness_level: RobustnessLevel = RobustnessLevel.FRAGILE
    checks: list[ValidationCheckResult] = Field(default_factory=list)
    exceptions_applied: list[dict[str, Any]] = Field(default_factory=list)
    """Auditable records of every legitimate-activity exception considered,
    including ones that did NOT match (never silently suppress)."""
    downgrade: dict[str, Any] | None = None
    """Present when ARDE reduced severity: reason + before/after."""
    validation_version: str = ARDE_VALIDATION_VERSION
