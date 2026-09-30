"""Part 4: ARDE validation and explainability layer.

ARDE (Aegivion Detection Evidence Review) receives candidate findings
from the Part 3 scoring stack and challenges them BEFORE release:

- Is the evidence internally consistent?
- Could this be legitimate high-volume activity?
- Could telemetry be incomplete?
- Are the observed signals mutually supportive?
- Is the model overreacting to one feature?

The layer is intentionally conservative: it can downgrade, require
review, or reject; it can never upgrade a finding, never suppress one
silently, and never touch cloud infrastructure (remediation belongs to
the separate Aegivion remediation layer).
"""

from __future__ import annotations

from .approved_activities import (
    APPROVED_ACTIVITY_KINDS,
    ApprovedActivityKind,
    ApprovedActivityProfile,
    ApprovedActivityRegistry,
)
from .audit import AuditEntry, AuditLog
from .consistency import ARDEContext, ConsistencyEngine
from .explain import ExplainabilityBuilder, FindingExplanation
from .formatter import format_finding_report
from .integration import explanation_of, outcome_of, report_of, validate_and_attach
from .models import (
    ARDE_VALIDATION_VERSION,
    CheckStatus,
    CheckSeverity,
    RobustnessLevel,
    ValidationCheckResult,
    ValidationStatus,
)
from .robustness import RobustnessHarness, RobustnessReport, RobustnessScenario, ScenarioResult
from .validator import ARDEValidator, ARDEValidatorConfig, ValidationOutcome

__all__ = [
    "APPROVED_ACTIVITY_KINDS",
    "ARDEContext",
    "ARDEValidator",
    "ARDEValidatorConfig",
    "ARDE_VALIDATION_VERSION",
    "ApprovedActivityKind",
    "ApprovedActivityProfile",
    "ApprovedActivityRegistry",
    "AuditEntry",
    "AuditLog",
    "CheckSeverity",
    "CheckStatus",
    "ConsistencyEngine",
    "ExplainabilityBuilder",
    "FindingExplanation",
    "RobustnessHarness",
    "RobustnessLevel",
    "RobustnessReport",
    "RobustnessScenario",
    "ScenarioResult",
    "ValidationCheckResult",
    "ValidationOutcome",
    "ValidationStatus",
    "explanation_of",
    "format_finding_report",
    "outcome_of",
    "report_of",
    "validate_and_attach",
]
