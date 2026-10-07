"""False-positive defense & exception context — **Part 6**.

ARDE's second question is always *"could this be legitimate?"*. This
module answers it with two mechanisms, both **annotation-only**:

1. **Context engine** (:class:`ContextEngine`) — recognizes the
   spec's nine known-legitimate patterns. Recognition comes from
   two sources, and both are auditable:

   - declared :class:`~detection.cloud_destruction.legitimate.ApprovedActivityProfile`
     objects (evaluated by :func:`match_profile`), and
   - telemetry-pattern recognition (:data:`PATTERN_RECOGNIZERS`):
     e.g. S3 ``LifecycleExpiration`` raw actions, automation-driven
     snapshot cleanup, CI/CD service principals. Each recognizer
     records *why* it fired, on which evidence.

2. **Exception system** (:class:`ExceptionRecord` /
   :class:`ExceptionRegistry`) — durable, scoped, owned, expiring
   analyst decisions. An exception carries ``exception_id``,
   ``scope``, ``owner``, ``created_at``, ``expires_at``, ``reason``
   and ``approval_state``.

**Hard rule: nothing ever silently suppresses a finding.** A
matching profile or an approved exception produces an
:class:`ContextAnnotation` that is *attached to the finding and
surfaced in the explanation* (as contradicting evidence). The
detector still emits the finding; triage humans decide. The
:class:`ContextAnnotation` type makes this mechanical: it has no
``suppress`` field, and :func:`apply_exceptions` returns the
finding unchanged — only annotated.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from algo.detection.cloud_destruction.exceptions import (
    CloudDestructionError,
)
from algo.detection.cloud_destruction.finding import DestructionFinding
from algo.detection.cloud_destruction.legitimate import (
    ActivityContext,
    ApprovedActivityProfile,
    match_profile,
)
from algo.detection.cloud_destruction.registry import CONTEXT_VERSION
from algo.detection.cloud_destruction.schemas import (
    ActionCategory,
    DestructiveActivitySession,
    ResourceActivityEvent,
)

__all__ = [
    "APPROVAL_STATES",
    "ApprovalState",
    "ContextAnnotation",
    "ContextEngine",
    "ExceptionRecord",
    "ExceptionRegistry",
    "ExceptionScope",
    "LegitimateActivity",
    "apply_exceptions",
    "spec_activity_for",
]


class LegitimateActivity(str, Enum):
    """The nine known-legitimate patterns (spec vocabulary).

    Mapped onto the narrower
    :class:`~detection.cloud_destruction.legitimate.ApprovedActivityProfile`
    taxonomy via :data:`SPEC_TO_PROFILE_ACTIVITY`.
    """

    S3_LIFECYCLE_EXPIRATION = "s3_lifecycle_expiration"
    BACKUP_RETENTION_CLEANUP = "backup_retention_cleanup"
    SCHEDULED_SNAPSHOT_CLEANUP = "scheduled_snapshot_cleanup"
    CICD_DEPLOYMENT = "cicd_deployment"
    DATABASE_MAINTENANCE = "database_maintenance"
    RESOURCE_MIGRATION = "resource_migration"
    DISASTER_RECOVERY_TESTING = "disaster_recovery_testing"
    BULK_DATA_PROCESSING = "bulk_data_processing"
    APPROVED_INFRASTRUCTURE_CHANGE = "approved_infrastructure_change"


#: Spec activity -> internal approved-profile activity.
SPEC_TO_PROFILE_ACTIVITY: dict[str, str] = {
    LegitimateActivity.S3_LIFECYCLE_EXPIRATION.value: "lifecycle_cleanup",
    LegitimateActivity.BACKUP_RETENTION_CLEANUP.value: "backup_retention",
    LegitimateActivity.SCHEDULED_SNAPSHOT_CLEANUP.value: "scheduled_maintenance",
    LegitimateActivity.CICD_DEPLOYMENT.value: "cicd_deployment",
    LegitimateActivity.DATABASE_MAINTENANCE.value: "database_maintenance",
    LegitimateActivity.RESOURCE_MIGRATION.value: "migration",
    LegitimateActivity.DISASTER_RECOVERY_TESTING.value: "scheduled_maintenance",
    LegitimateActivity.BULK_DATA_PROCESSING.value: "batch_processing",
    LegitimateActivity.APPROVED_INFRASTRUCTURE_CHANGE.value: "scheduled_maintenance",
}


def spec_activity_for(profile_activity: Optional[str]) -> Optional[str]:
    """Reverse-map an internal profile activity to the spec vocabulary."""
    if not profile_activity:
        return None
    for spec_activity, internal in SPEC_TO_PROFILE_ACTIVITY.items():
        if internal == profile_activity:
            return spec_activity
    return None


class ExceptionScope(str, Enum):
    """Breadth of an exception record."""

    GLOBAL = "global"
    ACCOUNT = "account"
    ACTOR = "actor"
    RESOURCE = "resource"
    SESSION = "session"


class ApprovalState(str, Enum):
    """Lifecycle state of an exception record."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


APPROVAL_STATES = tuple(state.value for state in ApprovalState)


class ExceptionRecord(BaseModel):
    """A durable, auditable analyst decision about legitimate activity.

    Stored exactly as the spec requires: ``exception_id``, ``scope``,
    ``owner``, ``created_at``, ``expires_at``, ``reason``,
    ``approval_state``. Only ``APPROVED`` records in-date can produce
    an annotation — and even then they annotate, never suppress.
    """

    model_config = ConfigDict(frozen=True)

    exception_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scope: ExceptionScope = ExceptionScope.GLOBAL
    owner: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    reason: str = ""
    approval_state: ApprovalState = ApprovalState.PENDING

    # optional scope refinement (must agree with ``scope``)
    activity: Optional[LegitimateActivity] = None
    account_ids: tuple[str, ...] = Field(default_factory=tuple)
    actor_ids: tuple[str, ...] = Field(default_factory=tuple)
    resource_ids: tuple[str, ...] = Field(default_factory=tuple)
    session_ids: tuple[str, ...] = Field(default_factory=tuple)

    def is_active(self, *, now: Optional[datetime] = None) -> bool:
        """Approved and not expired (and not revoked/rejected)."""
        if self.approval_state is not ApprovalState.APPROVED:
            return False
        if self.expires_at is None:
            return True
        reference = now if now is not None else datetime.now(timezone.utc)
        return reference <= self.expires_at

    def matches(
        self,
        session: DestructiveActivitySession,
        activity: Optional[str] = None,
    ) -> bool:
        """Does this record's scope cover the session?"""
        if self.scope is ExceptionScope.GLOBAL:
            return True
        if self.scope is ExceptionScope.SESSION:
            return not self.session_ids or session.session_id in self.session_ids
        if self.scope is ExceptionScope.ACCOUNT:
            return not self.account_ids or session.account_id in self.account_ids
        if self.scope is ExceptionScope.ACTOR:
            return not self.actor_ids or session.actor_id in self.actor_ids
        if self.scope is ExceptionScope.RESOURCE:
            touched = set(session.resources_touched)
            return bool(self.resource_ids) and bool(touched & set(self.resource_ids))
        return False

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "exception_id": self.exception_id,
            "scope": self.scope.value,
            "owner": self.owner,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "reason": self.reason,
            "approval_state": self.approval_state.value,
            "activity": self.activity.value if self.activity else None,
        }


class ExceptionRegistry:
    """Durable store of exception records (annotate-only semantics)."""

    def __init__(self, records: Optional[Sequence[ExceptionRecord]] = None) -> None:
        self._records: dict[str, ExceptionRecord] = {
            record.exception_id: record for record in (records or [])
        }

    def add(self, record: ExceptionRecord) -> ExceptionRecord:
        """Store a record; returns it. Duplicate ids are rejected."""
        if record.exception_id in self._records:
            raise CloudDestructionError(
                f"exception {record.exception_id} already registered"
            )
        self._records[record.exception_id] = record
        return record

    def get(self, exception_id: str) -> Optional[ExceptionRecord]:
        return self._records.get(exception_id)

    def revoke(self, exception_id: str, *, now: Optional[datetime] = None) -> bool:
        """Mark a record REVOKED (stored copy replaced)."""
        record = self._records.get(exception_id)
        if record is None:
            return False
        self._records[exception_id] = record.model_copy(
            update={"approval_state": ApprovalState.REVOKED}
        )
        return True

    def evaluate(
        self,
        session: DestructiveActivitySession,
        *,
        activity: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> tuple[ExceptionRecord, ...]:
        """Active, in-scope, approved records for this session."""
        # ``activity`` arrives in the internal profile vocabulary
        # (e.g. ``lifecycle_cleanup``); records store the spec
        # vocabulary (e.g. ``s3_lifecycle_expiration``).
        spec_activity = spec_activity_for(activity) if activity else None
        matches = []
        for record in self._records.values():
            if not record.is_active(now=now):
                continue
            if spec_activity is not None and record.activity is not None:
                record_activity = (
                    record.activity.value
                    if isinstance(record.activity, LegitimateActivity)
                    else record.activity
                )
                if record_activity != spec_activity:
                    continue
            if record.matches(session, activity=activity):
                matches.append(record)
        return tuple(matches)


class _PatternHit(BaseModel):
    """One telemetry-pattern recognition result."""

    model_config = ConfigDict(frozen=True)

    activity: LegitimateActivity
    evidence: tuple[str, ...] = Field(default_factory=tuple)
    confidence: str = "indicative"
    """``indicative`` (telemetry pattern) vs ``declared`` (profile)."""


def _raw_actions(events: Sequence[ResourceActivityEvent]) -> list[str]:
    return [
        (event.raw_action or "").lower()
        for event in events
        if event.raw_action
    ]


def _recognize_lifecycle_expiration(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> Optional[_PatternHit]:
    raw = " ".join(_raw_actions(events))
    lifecycle_hits = [
        event.event_id
        for event in events
        if event.raw_action
        and "lifecycle" in event.raw_action.lower()
        and event.action_category is ActionCategory.DELETE
    ]
    if lifecycle_hits:
        return _PatternHit(
            activity=LegitimateActivity.S3_LIFECYCLE_EXPIRATION,
            evidence=(
                f"{len(lifecycle_hits)} lifecycle-driven delete events "
                f"(e.g. {lifecycle_hits[0]})",
            ),
        )
    if "lifecycleexpiration" in raw:
        return _PatternHit(
            activity=LegitimateActivity.S3_LIFECYCLE_EXPIRATION,
            evidence=("raw action reference contains LifecycleExpiration",),
        )
    return None


def _recognize_backup_retention(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> Optional[_PatternHit]:
    if session.backup_deletions <= 0:
        return None
    retention = [
        event.event_id
        for event in events
        if event.raw_action
        and ("retention" in event.raw_action.lower()
             or "expire" in event.raw_action.lower())
        and event.action_category
        in (ActionCategory.BACKUP_DELETE, ActionCategory.RECOVERY_POINT_DELETE)
    ]
    if retention:
        return _PatternHit(
            activity=LegitimateActivity.BACKUP_RETENTION_CLEANUP,
            evidence=(
                f"{len(retention)} retention-driven recovery-point deletions "
                f"(e.g. {retention[0]})",
            ),
        )
    return None


def _recognize_scheduled_snapshot_cleanup(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> Optional[_PatternHit]:
    if session.snapshot_deletions <= 0:
        return None
    automation = [
        event.event_id
        for event in events
        if event.actor_type.value in ("aws_service", "service_account")
        and event.action_category is ActionCategory.SNAPSHOT_DELETE
    ]
    if automation:
        return _PatternHit(
            activity=LegitimateActivity.SCHEDULED_SNAPSHOT_CLEANUP,
            evidence=(
                f"{len(automation)} service-principal snapshot deletions "
                f"(e.g. {automation[0]})",
            ),
        )
    return None


def _recognize_cicd(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> Optional[_PatternHit]:
    if not events:
        return None
    principals = {
        event.actor_id
        for event in events
        if event.actor_id
        and (
            "deploy" in event.actor_id.lower()
            or "pipeline" in event.actor_id.lower()
            or "ci" in event.actor_id.lower().split(".")
            or event.actor_type.value in ("aws_service", "service_account")
        )
    }
    modifying = all(
        event.action_category
        in (ActionCategory.CREATE, ActionCategory.MODIFY)
        for event in events
    )
    if principals and modifying:
        return _PatternHit(
            activity=LegitimateActivity.CICD_DEPLOYMENT,
            evidence=(
                "all events are create/modify from deployment principals "
                f"({', '.join(sorted(principals)[:3])})",
            ),
        )
    return None


def _recognize_database_maintenance(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> Optional[_PatternHit]:
    db_types = {
        event.resource_type.value
        for event in events
        if event.resource_type
        and event.resource_type.value
        in ("rds_instance", "rds_snapshot", "dynamodb_table", "database")
    }
    if not db_types:
        return None
    if any(
        event.action_category
        in (ActionCategory.MODIFY, ActionCategory.REWRITE, ActionCategory.DELETE)
        for event in events
    ):
        return _PatternHit(
            activity=LegitimateActivity.DATABASE_MAINTENANCE,
            evidence=(
                f"maintenance-shaped activity on database resources "
                f"({', '.join(sorted(db_types))})",
            ),
        )
    return None


def _recognize_migration(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> Optional[_PatternHit]:
    has_restore = any(
        event.action_category is ActionCategory.RESTORE for event in events
    )
    has_copy = any(
        event.action_category is ActionCategory.CREATE for event in events
    )
    has_delete = any(
        event.action_category
        in (ActionCategory.DELETE, ActionCategory.REWRITE)
        for event in events
    )
    if has_restore and (has_copy or has_delete):
        return _PatternHit(
            activity=LegitimateActivity.RESOURCE_MIGRATION,
            evidence=(
                "restore-then-modify pattern consistent with resource migration",
            ),
        )
    return None


def _recognize_dr_testing(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> Optional[_PatternHit]:
    user_agent = " ".join(
        (event.user_agent or "") for event in events if event.user_agent
    ).lower()
    parameters = " ".join(
        str(event.request_parameters or "") for event in events
    ).lower()
    markers = ("dr-test", "drill", "disaster-recovery", "game-day")
    if any(marker in user_agent or marker in parameters for marker in markers):
        return _PatternHit(
            activity=LegitimateActivity.DISASTER_RECOVERY_TESTING,
            evidence=("telemetry carries DR-test/drill markers",),
        )
    return None


def _recognize_bulk_processing(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> Optional[_PatternHit]:
    rewrite_only = bool(events) and all(
        event.action_category
        in (ActionCategory.REWRITE, ActionCategory.MODIFY)
        for event in events
    )
    if rewrite_only and session.rewrite_count >= 10:
        return _PatternHit(
            activity=LegitimateActivity.BULK_DATA_PROCESSING,
            evidence=(
                f"{session.rewrite_count} rewrite/modify events without any "
                "deletion signal (bulk transform pattern)",
            ),
        )
    return None


def _recognize_infrastructure_change(
    session: DestructiveActivitySession,
    events: Sequence[ResourceActivityEvent],
) -> Optional[_PatternHit]:
    if not events:
        return None
    all_policy_or_protection = all(
        event.action_category
        in (
            ActionCategory.PROTECTION_CHANGE,
            ActionCategory.POLICY_CHANGE,
            ActionCategory.CREATE,
        )
        for event in events
    )
    if all_policy_or_protection and session.protection_changes > 0:
        return _PatternHit(
            activity=LegitimateActivity.APPROVED_INFRASTRUCTURE_CHANGE,
            evidence=(
                f"{session.protection_changes} protection/policy-change events "
                "without destructive deletion (infrastructure change pattern)",
            ),
        )
    return None


#: Telemetry-pattern recognizers. Each returns a hit or ``None``;
#: recognizers are pure functions of (session, events).
PATTERN_RECOGNIZERS: tuple[
    Callable[[DestructiveActivitySession, Sequence[ResourceActivityEvent]],
             Optional[_PatternHit]],
    ...
] = (
    _recognize_lifecycle_expiration,
    _recognize_backup_retention,
    _recognize_scheduled_snapshot_cleanup,
    _recognize_cicd,
    _recognize_database_maintenance,
    _recognize_migration,
    _recognize_dr_testing,
    _recognize_bulk_processing,
    _recognize_infrastructure_change,
)


class ContextAnnotation(BaseModel):
    """Legitimate-activity context attached to a finding.

    This type intentionally has **no suppression flag**: recognition
    and exceptions annotate, they never remove a finding from the
    detector's output. Consumers (triage, response orchestrator)
    see the annotation and decide.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str
    session_id: str
    context_version: str = CONTEXT_VERSION
    approved_activity: Optional[ActivityContext] = None
    recognized_patterns: tuple[_PatternHit, ...] = Field(default_factory=tuple)
    exceptions: tuple[ExceptionRecord, ...] = Field(default_factory=tuple)

    @property
    def has_context(self) -> bool:
        return bool(
            self.approved_activity or self.recognized_patterns or self.exceptions
        )

    def describe(self) -> list[str]:
        """Human-readable annotations (used as contradicting evidence)."""
        notes: list[str] = []
        if self.approved_activity is not None:
            spec = spec_activity_for(self.approved_activity.justification)
            label = spec or self.approved_activity.justification
            notes.append(
                f"declared legitimate activity ({label}, profile "
                f"{self.approved_activity.profile_id}, constraints: "
                f"{', '.join(self.approved_activity.matched_constraints)})"
            )
        for hit in self.recognized_patterns:
            notes.append(
                f"telemetry consistent with {hit.activity.value}: "
                + "; ".join(hit.evidence)
            )
        for record in self.exceptions:
            notes.append(
                f"approved exception {record.exception_id} (owner "
                f"{record.owner}, scope {record.scope.value}): {record.reason}"
            )
        return notes

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "session_id": self.session_id,
            "context_version": self.context_version,
            "approved_activity": (
                self.approved_activity.model_dump()
                if self.approved_activity is not None
                else None
            ),
            "recognized_patterns": [
                {"activity": hit.activity.value, "evidence": list(hit.evidence)}
                for hit in self.recognized_patterns
            ],
            "exceptions": [record.to_log_dict() for record in self.exceptions],
        }


class ContextEngine:
    """Recognizes known-legitimate patterns and applies exceptions.

    Pure evaluation: reads the session + telemetry + declared
    profiles + exception registry, and returns a
    :class:`ContextAnnotation`. It cannot modify a finding — use
    :func:`apply_exceptions` for the (still non-suppressing)
    annotation step.
    """

    def __init__(
        self,
        profiles: Optional[Sequence[ApprovedActivityProfile]] = None,
        exceptions: Optional[ExceptionRegistry] = None,
        *,
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._profiles = list(profiles or [])
        self._exceptions = exceptions or ExceptionRegistry()
        self._now = now

    def evaluate(
        self,
        finding: DestructionFinding,
        session: DestructiveActivitySession,
        events: Sequence[ResourceActivityEvent] = (),
    ) -> ContextAnnotation:
        approved = match_profile(session, self._profiles, events)
        hits = tuple(
            hit
            for recognizer in PATTERN_RECOGNIZERS
            if (hit := recognizer(session, events)) is not None
        )
        activity_name = (
            approved.justification if approved is not None else None
        )
        exception_records = self._exceptions.evaluate(
            session,
            activity=activity_name,
            now=self._now() if self._now else None,
        )
        return ContextAnnotation(
            finding_id=finding.finding_id,
            session_id=session.session_id,
            approved_activity=approved,
            recognized_patterns=hits,
            exceptions=exception_records,
        )


def apply_exceptions(
    finding: DestructionFinding,
    annotation: ContextAnnotation,
) -> DestructionFinding:
    """Attach a context annotation to a finding — **without mutating risk**.

    Returns a shallow copy of the finding whose ``raw`` block carries
    the annotation (and nothing else). The finding's severity, risk,
    confidence and evidence are untouched: exceptions never suppress
    or soften a finding, they only make the analyst's context
    machine-readable downstream.
    """
    if not annotation.has_context:
        return finding
    raw = dict(finding.raw)
    raw["context_annotation"] = annotation.to_log_dict()
    return DestructionFinding(
        finding_id=finding.finding_id,
        session_id=finding.session_id,
        detector_name=finding.detector_name,
        severity=finding.severity,
        risk_score=finding.risk_score,
        confidence_score=finding.confidence_score,
        actor_id=finding.actor_id,
        account_id=finding.account_id,
        observed_at=finding.observed_at,
        model_name=finding.model_name,
        model_version=finding.model_version,
        feature_version=finding.feature_version,
        baseline_version=finding.baseline_version,
        scoring_version=finding.scoring_version,
        rule_version=finding.rule_version,
        confidence_version=finding.confidence_version,
        severity_version=finding.severity_version,
        risk_contributions=dict(finding.risk_contributions),
        confidence_factors=dict(finding.confidence_factors),
        missing_evidence=tuple(finding.missing_evidence),
        approved_activity=finding.approved_activity,
        event_ids=tuple(finding.event_ids),
        resources_touched=tuple(finding.resources_touched),
        raw=raw,
    )
