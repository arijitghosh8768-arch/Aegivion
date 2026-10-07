"""Response orchestration — **Part 4**.

Turns Part 3 findings into an **auditable, defensive response plan**.
The orchestrator recommends and dispatches — it never performs cloud
actions itself. Every action runs through an *injected handler*
(callable), so this package holds no cloud credentials and no SDK
clients, and nothing irreversible happens unless a caller explicitly
opts out of dry-run mode.

Design rules enforced here:

1. **Defensive only.** The action vocabulary is containment,
   evidence and notification actions (notify, escalate, revoke,
   isolate, quarantine, collect forensics, monitor). No action in
   this module deletes, encrypts or destroys anything.
2. **Severity drives the playbook, never volume.** The mapping is a
   versioned policy: ``CRITICAL`` -> containment set,
   ``HIGH`` -> escalation + session revocation,
   ``MEDIUM`` -> notify + ticket, ``LOW`` -> monitor only.
3. **Dry-run by default.** ``execute()`` is a no-op unless the
   orchestrator was constructed with ``dry_run=False``.
4. **Approval gates irreversible actions.** Revocations, disables,
   isolation and quarantine require the caller to present the
   action's idempotency key as explicitly approved.
5. **Nothing is silently dropped.** Every planned action ends in a
   recorded status (``executed`` / ``skipped_approval`` /
   ``skipped_cooldown`` / ``skipped_no_handler`` / ``failed``);
   handler exceptions are captured on the action, never raised
   mid-plan.
6. **Deterministic and idempotent.** Action ids and idempotency
   keys are content digests (finding + action + policy version), so
   the same findings + policy produce the same plan, and replays do
   not double-fire approved actions.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from algo.detection.cloud_destruction.finding import DestructionFinding, Severity
from algo.detection.cloud_destruction.registry import RESPONSE_VERSION, content_digest

__all__ = [
    "ActionStatus",
    "ResponseAction",
    "ResponseActionType",
    "ResponseOrchestrator",
    "ResponsePlan",
    "ResponsePolicy",
]


class ResponseActionType(str, Enum):
    """Defensive response actions (containment / evidence / notify).

    Every value is non-destructive: the worst action here revokes
    access or isolates a resource — data is never deleted.
    """

    MONITOR = "monitor"
    NOTIFY = "notify"
    OPEN_TICKET = "open_ticket"
    ESCALATE = "escalate"
    COLLECT_FORENSICS = "collect_forensics"
    REVOKE_SESSION = "revoke_session"
    REVOKE_CREDENTIALS = "revoke_credentials"
    DISABLE_USER = "disable_user"
    ISOLATE_RESOURCE = "isolate_resource"
    QUARANTINE_RESOURCE = "quarantine_resource"


#: Actions that change access/isolation state — irreversible-ish,
#: so enforcement requires explicit per-action approval.
APPROVAL_REQUIRED: frozenset[ResponseActionType] = frozenset(
    {
        ResponseActionType.REVOKE_SESSION,
        ResponseActionType.REVOKE_CREDENTIALS,
        ResponseActionType.DISABLE_USER,
        ResponseActionType.ISOLATE_RESOURCE,
        ResponseActionType.QUARANTINE_RESOURCE,
    }
)

_SEVERITY_PLAYBOOK: dict[Severity, tuple[ResponseActionType, ...]] = {
    Severity.LOW: (ResponseActionType.MONITOR,),
    Severity.MEDIUM: (ResponseActionType.NOTIFY, ResponseActionType.OPEN_TICKET),
    Severity.HIGH: (
        ResponseActionType.NOTIFY,
        ResponseActionType.ESCALATE,
        ResponseActionType.COLLECT_FORENSICS,
        ResponseActionType.REVOKE_SESSION,
    ),
    Severity.CRITICAL: (
        ResponseActionType.NOTIFY,
        ResponseActionType.ESCALATE,
        ResponseActionType.COLLECT_FORENSICS,
        ResponseActionType.REVOKE_SESSION,
        ResponseActionType.REVOKE_CREDENTIALS,
        ResponseActionType.QUARANTINE_RESOURCE,
    ),
}

#: Severity -> dispatch priority (1 runs first).
_SEVERITY_PRIORITY: dict[Severity, int] = {
    Severity.CRITICAL: 1,
    Severity.HIGH: 2,
    Severity.MEDIUM: 3,
    Severity.LOW: 4,
}


class ResponsePolicy(BaseModel):
    """Versioned severity -> response playbook."""

    model_config = ConfigDict(frozen=True)

    version: str = RESPONSE_VERSION
    playbook: dict[Severity, tuple[ResponseActionType, ...]] = Field(
        default_factory=lambda: {k: tuple(v) for k, v in _SEVERITY_PLAYBOOK.items()}
    )
    cooldown_minutes: int = Field(default=60, ge=0)
    """Per-actor + per-action dispatch cooldown (0 disables dedupe)."""
    max_actions_per_finding: int = Field(default=8, ge=1)
    """Hard cap on actions planned for a single finding."""

    def actions_for(self, severity: Severity) -> tuple[ResponseActionType, ...]:
        return tuple(self.playbook.get(severity, (ResponseActionType.MONITOR,)))


class ActionStatus(str, Enum):
    """Terminal state of one planned response action."""

    PLANNED = "planned"
    EXECUTED = "executed"
    SKIPPED_APPROVAL = "skipped_approval"
    SKIPPED_COOLDOWN = "skipped_cooldown"
    SKIPPED_NO_HANDLER = "skipped_no_handler"
    FAILED = "failed"


@dataclass
class ResponseAction:
    """One planned (or executed) response action — audit-complete."""

    action_id: str
    finding_id: str
    session_id: str
    actor_id: Optional[str]
    account_id: Optional[str]
    action_type: ResponseActionType
    severity: Severity
    priority: int
    rationale: str
    requires_approval: bool
    policy_version: str
    idempotency_key: str
    versions: dict[str, Any] = field(default_factory=dict)
    status: ActionStatus = ActionStatus.PLANNED
    handler_result: Any = None
    error: Optional[str] = None

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "finding_id": self.finding_id,
            "session_id": self.session_id,
            "actor_id": self.actor_id,
            "account_id": self.account_id,
            "action_type": self.action_type.value,
            "severity": self.severity.value,
            "priority": self.priority,
            "rationale": self.rationale,
            "requires_approval": self.requires_approval,
            "policy_version": self.policy_version,
            "idempotency_key": self.idempotency_key,
            "status": self.status.value,
            "error": self.error,
            "versions": self.versions,
        }


@dataclass
class ResponsePlan:
    """An ordered, deduplicated response plan for a set of findings."""

    actions: tuple[ResponseAction, ...] = ()
    dry_run: bool = True
    cooldown_skips: int = 0
    policy_version: str = RESPONSE_VERSION

    @property
    def total_actions(self) -> int:
        return len(self.actions)

    @property
    def executed(self) -> int:
        return sum(1 for a in self.actions if a.status is ActionStatus.EXECUTED)

    @property
    def approval_required(self) -> int:
        return sum(1 for a in self.actions if a.requires_approval)

    def by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for action in self.actions:
            key = action.status.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "policy_version": self.policy_version,
            "cooldown_skips": self.cooldown_skips,
            "total_actions": self.total_actions,
            "approval_required": self.approval_required,
            "by_status": self.by_status(),
            "actions": [a.to_log_dict() for a in self.actions],
        }


#: Handler signature: receives the planned action, returns any result.
ResponseHandler = Callable[[ResponseAction], Any]


class ResponseOrchestrator:
    """Builds and (optionally) executes response plans from findings.

    The orchestrator itself never touches a cloud API: enforcement
    goes exclusively through caller-supplied ``handlers``. With
    ``dry_run=True`` (default) ``execute()`` returns the plan
    untouched — nothing runs, nothing is approved, nothing fires.
    """

    def __init__(
        self,
        policy: Optional[ResponsePolicy] = None,
        *,
        handlers: Optional[dict[ResponseActionType, ResponseHandler]] = None,
        dry_run: bool = True,
        cooldown_state: Optional[dict[tuple[str, str], float]] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._policy = policy or ResponsePolicy()
        self._handlers = dict(handlers or {})
        self._dry_run = dry_run
        # (actor_key, action_type) -> epoch seconds of last dispatch.
        self._cooldown_state: dict[tuple[str, str], float] = (
            cooldown_state if cooldown_state is not None else {}
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def policy(self) -> ResponsePolicy:
        return self._policy

    # ------------------------------------------------------------------ #
    # Planning
    # ------------------------------------------------------------------ #

    def plan(self, findings: Sequence[DestructionFinding]) -> ResponsePlan:
        """Build a deterministic, severity-ordered response plan.

        Ordering: severity priority (CRITICAL first), then risk
        descending, then finding id — so the plan is stable for the
        same input regardless of input order.
        """
        ordered = sorted(
            findings,
            key=lambda f: (
                _SEVERITY_PRIORITY.get(f.severity, 9),
                -f.risk_score,
                f.finding_id,
            ),
        )
        now = self._clock()
        actions: list[ResponseAction] = []
        cooldown_skips = 0
        for finding in ordered:
            playbook = self._policy.actions_for(finding.severity)[
                : self._policy.max_actions_per_finding
            ]
            for action_type in playbook:
                action = self._build_action(finding, action_type, now)
                if self._in_cooldown(action, now):
                    cooldown_skips += 1
                    action.status = ActionStatus.SKIPPED_COOLDOWN
                    actions.append(action)
                    continue
                actions.append(action)
                self._cooldown_state[(self._actor_key(action), action.action_type.value)] = (
                    now.timestamp()
                )
        return ResponsePlan(
            actions=tuple(actions),
            dry_run=self._dry_run,
            cooldown_skips=cooldown_skips,
            policy_version=self._policy.version,
        )

    def _build_action(
        self,
        finding: DestructionFinding,
        action_type: ResponseActionType,
        now: datetime,
    ) -> ResponseAction:
        payload = f"{finding.finding_id}|{action_type.value}|{self._policy.version}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        idempotency = content_digest(
            {
                "finding_id": finding.finding_id,
                "session_id": finding.session_id,
                "actor_id": finding.actor_id,
                "action_type": action_type.value,
                "policy_version": self._policy.version,
            }
        )
        return ResponseAction(
            action_id=f"resp-{digest[:16]}",
            finding_id=finding.finding_id,
            session_id=finding.session_id,
            actor_id=finding.actor_id,
            account_id=finding.account_id,
            action_type=action_type,
            severity=finding.severity,
            priority=_SEVERITY_PRIORITY.get(finding.severity, 9),
            rationale=(
                f"{finding.severity.value} severity destructive activity by "
                f"{finding.actor_id or 'unknown actor'} (risk={finding.risk_score:.3f}, "
                f"confidence={finding.confidence_score:.3f}) -> {action_type.value}"
            ),
            requires_approval=action_type in APPROVAL_REQUIRED,
            policy_version=self._policy.version,
            idempotency_key=idempotency,
            versions=dict(finding.to_log_dict().get("versions", {})),
        )

    # ------------------------------------------------------------------ #
    # Execution
    # ------------------------------------------------------------------ #

    def execute(
        self,
        plan: ResponsePlan,
        *,
        approved: Optional[set[str]] = None,
    ) -> ResponsePlan:
        """Execute a plan through injected handlers.

        Dry-run orchestrators return the plan unchanged. Otherwise
        each action is dispatched in order: approval-gated actions
        whose idempotency key (or action id) is absent from
        ``approved`` are recorded as ``skipped_approval``; actions
        without a registered handler are recorded as
        ``skipped_no_handler``; handler exceptions are captured as
        ``failed`` — one bad handler never aborts the plan.
        """
        if self._dry_run:
            return plan

        approved_keys = set(approved or set())
        executed: list[ResponseAction] = []
        now = self._clock()
        for action in plan.actions:
            if action.status is ActionStatus.SKIPPED_COOLDOWN:
                executed.append(action)
                continue
            if action.requires_approval and not self._is_approved(
                action, approved_keys
            ):
                action.status = ActionStatus.SKIPPED_APPROVAL
                executed.append(action)
                continue
            handler = self._handlers.get(action.action_type)
            if handler is None:
                action.status = ActionStatus.SKIPPED_NO_HANDLER
                executed.append(action)
                continue
            try:
                action.handler_result = handler(action)
                action.status = ActionStatus.EXECUTED
                self._cooldown_state[
                    (self._actor_key(action), action.action_type.value)
                ] = now.timestamp()
            except Exception as exc:  # noqa: BLE001 - captured per action
                action.status = ActionStatus.FAILED
                action.error = f"{type(exc).__name__}: {exc}"
            executed.append(action)
        return ResponsePlan(
            actions=tuple(executed),
            dry_run=False,
            cooldown_skips=plan.cooldown_skips,
            policy_version=plan.policy_version,
        )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _actor_key(action: ResponseAction) -> str:
        return action.actor_id or action.session_id

    def _in_cooldown(self, action: ResponseAction, now: datetime) -> bool:
        if self._policy.cooldown_minutes <= 0:
            return False
        last = self._cooldown_state.get((self._actor_key(action), action.action_type.value))
        if last is None:
            return False
        age_minutes = (now.timestamp() - last) / 60.0
        return age_minutes < self._policy.cooldown_minutes

    @staticmethod
    def _is_approved(action: ResponseAction, approved_keys: set[str]) -> bool:
        return action.idempotency_key in approved_keys or action.action_id in approved_keys
