"""Part 4 tests: response orchestration.

The orchestrator is defensive-only: it plans and (optionally)
dispatches containment / evidence / notification actions through
injected handlers. These tests pin the enforced rules:

- severity drives the playbook (never volume)
- dry-run by default; nothing runs unless explicitly enabled
- irreversible actions are approval-gated
- cooldown dedupes per actor + action
- plans are deterministic and content-addressed
- handler failures are captured, never abort the plan
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from algo.detection.cloud_destruction.finding import DestructionFinding, Severity
from algo.detection.cloud_destruction.response import (
    APPROVAL_REQUIRED,
    ActionStatus,
    ResponseActionType,
    ResponseOrchestrator,
    ResponsePolicy,
)
from algo.detection.cloud_destruction.registry import RESPONSE_VERSION

BASE_TIME = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)


def make_finding(
    finding_id: str = "fnd-1",
    severity: Severity = Severity.LOW,
    risk: float = 0.1,
    confidence: float = 0.9,
    actor: str = "alice.admin",
    session: str = "sess-1",
    account: str = "111122223333",
) -> DestructionFinding:
    return DestructionFinding(
        finding_id=finding_id,
        session_id=session,
        detector_name="aegivion.cloud_destruction",
        severity=severity,
        risk_score=risk,
        confidence_score=confidence,
        actor_id=actor,
        account_id=account,
        observed_at=BASE_TIME,
        model_name="isolation_forest",
        model_version="1.0.0",
        feature_version="1.0.0",
        baseline_version="b-1",
        scoring_version="1.0.0",
        rule_version="1.0.0",
    )


class TestResponsePolicy:
    def test_default_playbook_per_severity(self):
        policy = ResponsePolicy()
        assert policy.actions_for(Severity.LOW) == (ResponseActionType.MONITOR,)
        assert policy.actions_for(Severity.MEDIUM) == (
            ResponseActionType.NOTIFY,
            ResponseActionType.OPEN_TICKET,
        )
        assert ResponseActionType.REVOKE_SESSION in policy.actions_for(Severity.HIGH)
        critical = policy.actions_for(Severity.CRITICAL)
        assert ResponseActionType.REVOKE_CREDENTIALS in critical
        assert ResponseActionType.QUARANTINE_RESOURCE in critical

    def test_playbook_is_defensive_only(self):
        """Every playbook action is containment/evidence/notify — never destructive."""
        policy = ResponsePolicy()
        destructive_ish = {
            "delete",
            "destroy",
            "encrypt",
            "erase",
            "wipe",
            "remove",
        }
        for severity in Severity:
            for action in policy.actions_for(severity):
                assert not destructive_ish & set(action.value.split("_"))

    def test_empty_playbook_falls_back_to_monitor(self):
        policy = ResponsePolicy(playbook={})
        assert policy.actions_for(Severity.CRITICAL) == (ResponseActionType.MONITOR,)

    def test_unknown_severity_falls_back_to_monitor(self):
        policy = ResponsePolicy()
        assert policy.actions_for(None) == (ResponseActionType.MONITOR,)  # type: ignore[arg-type]


class TestPlanning:
    def test_plan_orders_severity_then_risk(self):
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0)
        )
        findings = [
            make_finding("low-risky", Severity.LOW, risk=0.9),
            make_finding("high-a", Severity.HIGH, risk=0.5),
            make_finding("crit", Severity.CRITICAL, risk=0.8),
            make_finding("high-b", Severity.HIGH, risk=0.7),
        ]
        plan = orchestrator.plan(findings)
        order = [a.finding_id for a in plan.actions]
        # CRITICAL first, then HIGH by risk desc, then LOW.
        first_critical = [i for i, fid in enumerate(order) if fid == "crit"][0]
        high_b = order.index("high-b")
        high_a = order.index("high-a")
        low = order.index("low-risky")
        assert first_critical < high_b < high_a < low

    def test_plan_is_deterministic_regardless_of_input_order(self):
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0)
        )
        findings = [
            make_finding("a", Severity.MEDIUM, risk=0.4),
            make_finding("b", Severity.HIGH, risk=0.6),
            make_finding("c", Severity.LOW, risk=0.2),
        ]
        forward = orchestrator.plan(findings)
        backward = orchestrator.plan(list(reversed(findings)))
        assert [a.action_id for a in forward.actions] == [
            a.action_id for a in backward.actions
        ]

    def test_action_ids_and_keys_are_content_digests(self):
        first = ResponseOrchestrator(policy=ResponsePolicy(cooldown_minutes=0))
        second = ResponseOrchestrator(policy=ResponsePolicy(cooldown_minutes=0))
        finding = make_finding(severity=Severity.HIGH)
        plan_a = first.plan([finding])
        plan_b = second.plan([finding])
        assert plan_a.actions[0].action_id == plan_b.actions[0].action_id
        assert plan_a.actions[0].idempotency_key == plan_b.actions[0].idempotency_key
        assert plan_a.actions[0].policy_version == RESPONSE_VERSION

    def test_plan_applies_cooldown_per_actor_and_action(self):
        orchestrator = ResponseOrchestrator()  # default 60-minute cooldown
        finding = make_finding(severity=Severity.LOW)
        first = orchestrator.plan([finding])
        assert first.cooldown_skips == 0
        second = orchestrator.plan([finding])
        assert second.cooldown_skips == len(second.actions)
        assert all(
            a.status is ActionStatus.SKIPPED_COOLDOWN for a in second.actions
        )

    def test_cooldown_expires(self):
        clock = {"now": BASE_TIME}

        def ticking_clock() -> datetime:
            return clock["now"]

        orchestrator = ResponseOrchestrator(clock=ticking_clock)
        finding = make_finding(severity=Severity.LOW)
        orchestrator.plan([finding])
        clock["now"] = BASE_TIME + timedelta(minutes=61)
        again = orchestrator.plan([finding])
        assert again.cooldown_skips == 0

    def test_max_actions_per_finding_caps_playbook(self):
        policy = ResponsePolicy(
            cooldown_minutes=0, max_actions_per_finding=2
        )
        orchestrator = ResponseOrchestrator(policy=policy)
        plan = orchestrator.plan([make_finding(severity=Severity.CRITICAL)])
        assert len(plan.actions) == 2
        # The cap keeps the highest-priority prefix of the playbook.
        assert [a.action_type for a in plan.actions] == [
            ResponseActionType.NOTIFY,
            ResponseActionType.ESCALATE,
        ]

    def test_rationale_mentions_severity_actor_and_scores(self):
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0)
        )
        plan = orchestrator.plan(
            [make_finding(severity=Severity.HIGH, risk=0.75, confidence=0.66)]
        )
        rationale = plan.actions[0].rationale
        assert "high" in rationale
        assert "alice.admin" in rationale
        assert "0.750" in rationale
        assert "0.660" in rationale


class TestExecution:
    def test_dry_run_is_default_and_is_a_noop(self):
        orchestrator = ResponseOrchestrator()  # dry_run=True
        assert orchestrator.plan([make_finding()]).dry_run is True
        plan = orchestrator.plan([make_finding(severity=Severity.HIGH)])
        executed = orchestrator.execute(plan, approved=set())
        assert executed is plan
        assert all(a.status is ActionStatus.PLANNED for a in executed.actions)

    def test_execute_without_handlers_records_skipped_no_handler(self):
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0), dry_run=False
        )
        plan = orchestrator.plan([make_finding(severity=Severity.LOW)])
        result = orchestrator.execute(plan)
        assert result.by_status() == {"skipped_no_handler": 1}

    def test_approval_gates_enforcement_actions(self):
        handled = {
            action: (lambda a: "ok") for action in ResponseActionType
        }
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0),
            handlers=handled,
            dry_run=False,
        )
        plan = orchestrator.plan([make_finding(severity=Severity.HIGH)])
        result = orchestrator.execute(plan)  # nothing approved
        by_type = {a.action_type: a.status for a in result.actions}
        assert by_type[ResponseActionType.NOTIFY] is ActionStatus.EXECUTED
        assert by_type[ResponseActionType.ESCALATE] is ActionStatus.EXECUTED
        assert (
            by_type[ResponseActionType.REVOKE_SESSION]
            is ActionStatus.SKIPPED_APPROVAL
        )

    def test_approval_accepts_idempotency_key_or_action_id(self):
        handled = {action: (lambda a: "ok") for action in ResponseActionType}
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0),
            handlers=handled,
            dry_run=False,
        )
        finding = make_finding(severity=Severity.HIGH)
        plan = orchestrator.plan([finding])
        revoke = next(
            a for a in plan.actions
            if a.action_type is ResponseActionType.REVOKE_SESSION
        )

        # Approve by idempotency key on a fresh plan:
        plan_key = orchestrator.plan([finding])
        result = orchestrator.execute(plan_key, approved={revoke.idempotency_key})
        by_type = {a.action_type: a.status for a in result.actions}
        assert by_type[ResponseActionType.REVOKE_SESSION] is ActionStatus.EXECUTED

        # Approve by action id on a fresh plan:
        plan_id = orchestrator.plan([finding])
        revoke_again = next(
            a for a in plan_id.actions
            if a.action_type is ResponseActionType.REVOKE_SESSION
        )
        result = orchestrator.execute(plan_id, approved={revoke_again.action_id})
        by_type = {a.action_type: a.status for a in result.actions}
        assert by_type[ResponseActionType.REVOKE_SESSION] is ActionStatus.EXECUTED

    def test_handler_exception_is_captured_not_raised(self):
        def boom(action):
            raise RuntimeError("cloud api down")

        handled = {
            ResponseActionType.NOTIFY: boom,
            ResponseActionType.OPEN_TICKET: (lambda a: "ticket-1"),
        }
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0),
            handlers=handled,
            dry_run=False,
        )
        plan = orchestrator.plan([make_finding(severity=Severity.MEDIUM)])
        result = orchestrator.execute(plan)  # must not raise
        by_type = {a.action_type: a for a in result.actions}
        assert by_type[ResponseActionType.NOTIFY].status is ActionStatus.FAILED
        assert "RuntimeError" in by_type[ResponseActionType.NOTIFY].error
        assert (
            by_type[ResponseActionType.OPEN_TICKET].status is ActionStatus.EXECUTED
        )

    def test_handler_result_is_recorded(self):
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0),
            handlers={ResponseActionType.NOTIFY: lambda a: "slack-ok"},
            dry_run=False,
        )
        plan = orchestrator.plan([make_finding(severity=Severity.MEDIUM)])
        result = orchestrator.execute(plan)
        notify = next(
            a for a in result.actions if a.action_type is ResponseActionType.NOTIFY
        )
        assert notify.status is ActionStatus.EXECUTED
        assert notify.handler_result == "slack-ok"

    def test_execute_preserves_cooldown_skips(self):
        orchestrator = ResponseOrchestrator(dry_run=False)
        finding = make_finding(severity=Severity.LOW)
        orchestrator.plan([finding])
        second = orchestrator.plan([finding])
        result = orchestrator.execute(second)
        assert result.cooldown_skips == len(second.actions)

    def test_non_dry_run_plan_is_marked_executed_mode(self):
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0), dry_run=False
        )
        plan = orchestrator.plan([make_finding()])
        result = orchestrator.execute(plan)
        assert result.dry_run is False


class TestAudit:
    def test_plan_counters(self):
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0)
        )
        plan = orchestrator.plan(
            [
                make_finding("a", Severity.HIGH),
                make_finding("b", Severity.LOW),
            ]
        )
        assert plan.total_actions == len(plan.actions)
        assert plan.approval_required == sum(
            1 for a in plan.actions if a.requires_approval
        )
        assert plan.executed == 0  # nothing executed until execute()
        assert plan.by_status() == {"planned": plan.total_actions}

    def test_approval_flag_matches_approval_required_set(self):
        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0)
        )
        plan = orchestrator.plan([make_finding(severity=Severity.CRITICAL)])
        for action in plan.actions:
            assert action.requires_approval == (action.action_type in APPROVAL_REQUIRED)

    def test_to_log_dict_is_json_serializable(self):
        import json

        orchestrator = ResponseOrchestrator(
            policy=ResponsePolicy(cooldown_minutes=0)
        )
        plan = orchestrator.plan([make_finding(severity=Severity.MEDIUM)])
        payload = json.dumps(plan.to_log_dict())
        assert plan.policy_version in payload
        assert "actions" in payload
