"""Part 6 — Security tests (deliverable 8).

Safe operation per the spec's SAFE OPERATION section: the detector
MUST NOT delete resources, disable users, destroy snapshots, modify
backups, encrypt data, or change IAM policies. It only observes,
scores, validates, and creates findings. Remediation remains a
separate Aegivion module (``response.py``) and is approval-gated
there — the detector itself never acts.
"""

from __future__ import annotations

import re
import socket
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from algo.detection.cloud_destruction.arde import ArdeValidator
from algo.detection.cloud_destruction.audit import (
    AuditAction,
    AuditLogger,
)
from algo.detection.cloud_destruction.context import (
    ApprovalState,
    ContextEngine,
    ExceptionRecord,
    ExceptionRegistry,
    ExceptionScope,
)
from algo.detection.cloud_destruction.detector import DestructionDetector
from algo.detection.cloud_destruction.exceptions import (
    CloudDestructionError,
)
from algo.detection.cloud_destruction.explainability import (
    FINDING_LABEL,
    DestructiveBehaviorCategory,
    build_explanation,
)
from algo.detection.cloud_destruction.response import (
    APPROVAL_REQUIRED,
    ActionStatus,
    ResponseActionType,
    ResponseOrchestrator,
)
from algo.detection.cloud_destruction.schemas import ActionCategory
from algo.detection.cloud_destruction.session import (
    DestructiveSessionBuilder,
)
from algo.detection.cloud_destruction.tests.helpers import (
    BASE_TIME,
    advance,
    make_event,
)

_PACKAGE = Path(__file__).resolve().parent.parent
_MODULES = sorted(_PACKAGE.glob("*.py"))

# Mutating cloud-API call shapes (``x.delete_...(``, ``x.put_...(`` …).
_MUTATING_CALL = re.compile(
    r"\.(delete|put|post|update|modify|disable|encrypt|revoke|"
    r"attach|detach|create)_[a-z_]+\("
)
# Local SQLAlchemy schema bootstrap — not a cloud mutation.
_LOCAL_DDL_ALLOWLIST = {"create_all"}

_BANNED_IMPORTS = (
    "import boto3",
    "from botocore",
    "import requests",
    "from requests",
    "import urllib",
    "from urllib",
    "import httpx",
    "from httpx",
)


def _destructive_burst():
    """Calibrated mixed burst: one CRITICAL-severity session."""
    categories = (
        ActionCategory.SNAPSHOT_DELETE,
        ActionCategory.BACKUP_DELETE,
        ActionCategory.RECOVERY_POINT_DELETE,
        ActionCategory.PROTECTION_CHANGE,
        ActionCategory.DELETE,
        ActionCategory.VERSION_DELETE,
    )
    return [
        make_event(
            event_id=f"e{i}",
            timestamp=advance(BASE_TIME, i),
            actor_id="attacker",
            action_category=categories[i % len(categories)],
            resource_id=f"res-{i % 7}",
        )
        for i in range(18)
    ]


def _record(**overrides) -> ExceptionRecord:
    payload: dict = {
        "owner": "analyst@corp.example",
        "created_at": BASE_TIME,
        "reason": "nightly snapshot cleanup",
        "approval_state": ApprovalState.APPROVED,
    }
    payload.update(overrides)
    return ExceptionRecord(**payload)


# ---------------------------------------------------------------------- #
# Safe operation: the detector is read-only
# ---------------------------------------------------------------------- #


class TestSafeOperation:
    def test_detect_opens_no_network_sockets(self, monkeypatch):
        def _forbidden(*args, **kwargs):
            raise AssertionError(
                "detector must not open network connections"
            )

        monkeypatch.setattr(socket, "socket", _forbidden)
        monkeypatch.setattr(socket, "create_connection", _forbidden)
        outcome = DestructionDetector().detect(_destructive_burst())
        assert outcome.findings

    def test_detector_package_has_no_cloud_sdk_or_http_imports(self):
        for path in _MODULES:
            source = path.read_text(encoding="utf-8")
            for banned in _BANNED_IMPORTS:
                assert banned not in source, (
                    f"{path.name} must not import {banned!r}"
                )

    def test_detector_source_issues_no_mutating_api_calls(self):
        for path in _MODULES:
            source = path.read_text(encoding="utf-8")
            for match in _MUTATING_CALL.finditer(source):
                method = match.group(0)[1 : match.group(0).index("(")]
                assert method in _LOCAL_DDL_ALLOWLIST, (
                    f"{path.name}: mutating call {match.group(0)!r}"
                )

    def test_response_orchestrator_is_dry_run_by_default(self):
        outcome = DestructionDetector().detect(_destructive_burst())
        orchestrator = ResponseOrchestrator()
        executed = orchestrator.execute(orchestrator.plan(outcome.findings))
        assert executed.dry_run is True
        assert executed.executed == 0
        assert all(
            action.status is ActionStatus.PLANNED
            for action in executed.actions
        )

    def test_destructive_response_actions_are_approval_gated(self):
        outcome = DestructionDetector().detect(_destructive_burst())
        orchestrator = ResponseOrchestrator(dry_run=False)
        executed = orchestrator.execute(
            orchestrator.plan(outcome.findings), approved=set()
        )
        # nothing ran: irreversible actions wait for explicit approval
        assert executed.executed == 0
        gated = [
            action for action in executed.actions
            if action.requires_approval
        ]
        assert gated
        assert all(
            action.status is ActionStatus.SKIPPED_APPROVAL
            for action in gated
        )

    def test_irreversible_action_types_require_approval(self):
        for action_type in (
            ResponseActionType.REVOKE_SESSION,
            ResponseActionType.REVOKE_CREDENTIALS,
            ResponseActionType.DISABLE_USER,
            ResponseActionType.ISOLATE_RESOURCE,
            ResponseActionType.QUARANTINE_RESOURCE,
        ):
            assert action_type in APPROVAL_REQUIRED


# ---------------------------------------------------------------------- #
# Input immutability: detection never rewrites its inputs
# ---------------------------------------------------------------------- #


class TestInputImmutability:
    def test_detect_leaves_input_events_untouched(self):
        events = _destructive_burst()
        before = [event.model_dump(mode="json") for event in events]
        DestructionDetector().detect(events)
        after = [event.model_dump(mode="json") for event in events]
        assert before == after
        assert len(events) == 18

    def test_validation_and_context_leave_sessions_untouched(self):
        outcome = DestructionDetector().detect(_destructive_burst())
        before = [
            session.model_dump(mode="json")
            for session in outcome.sessions
        ]
        validator = ArdeValidator()
        engine = ContextEngine()
        for session, finding, vector, risk, confidence in zip(
            outcome.sessions,
            outcome.findings,
            outcome.feature_vectors,
            outcome.risks,
            outcome.confidences,
        ):
            validator.validate(
                finding, session, vector, risk, confidence,
                _destructive_burst(),
            )
            engine.evaluate(finding, session, _destructive_burst())
        after = [
            session.model_dump(mode="json")
            for session in outcome.sessions
        ]
        assert before == after


# ---------------------------------------------------------------------- #
# Exception system integrity
# ---------------------------------------------------------------------- #


class TestExceptionIntegrity:
    def test_record_stores_the_spec_fields(self):
        record = _record(
            exception_id="exc-1",
            scope=ExceptionScope.GLOBAL,
            expires_at=None,
        )
        stored = record.to_log_dict()
        for field in (
            "exception_id", "scope", "owner", "created_at",
            "expires_at", "reason", "approval_state",
        ):
            assert field in stored
        assert stored["exception_id"] == "exc-1"
        assert stored["owner"] == "analyst@corp.example"
        assert stored["approval_state"] == "approved"

    def test_non_approved_states_never_annotate(self):
        sessions = DestructiveSessionBuilder().build_sessions(
            _destructive_burst()
        )
        for state in (
            ApprovalState.PENDING,
            ApprovalState.REJECTED,
            ApprovalState.EXPIRED,
            ApprovalState.REVOKED,
        ):
            registry = ExceptionRegistry(
                [_record(approval_state=state)]
            )
            assert registry.evaluate(sessions[0]) == ()

    def test_expired_record_is_inactive(self):
        expired = _record(expires_at=BASE_TIME - timedelta(hours=1))
        assert not expired.is_active(now=BASE_TIME)
        registry = ExceptionRegistry([expired])
        sessions = DestructiveSessionBuilder().build_sessions(
            _destructive_burst()
        )
        assert registry.evaluate(sessions[0], now=BASE_TIME) == ()

    def test_revocation_deactivates_record(self):
        registry = ExceptionRegistry(
            [_record(exception_id="exc-revoke")]
        )
        assert registry.revoke("exc-revoke", now=BASE_TIME)
        sessions = DestructiveSessionBuilder().build_sessions(
            _destructive_burst()
        )
        assert registry.evaluate(sessions[0], now=BASE_TIME) == ()

    def test_scope_is_enforced(self):
        sessions = DestructiveSessionBuilder().build_sessions(
            _destructive_burst()
        )
        foreign_actor = _record(
            scope=ExceptionScope.ACTOR,
            actor_ids=("somebody.else",),
        )
        assert not foreign_actor.matches(sessions[0])
        registry = ExceptionRegistry([foreign_actor])
        assert registry.evaluate(sessions[0], now=BASE_TIME) == ()

    def test_duplicate_exception_ids_rejected(self):
        registry = ExceptionRegistry()
        first = _record(exception_id="exc-dup")
        registry.add(first)
        with pytest.raises(CloudDestructionError):
            registry.add(_record(exception_id="exc-dup"))

    def test_approved_exception_annotates_but_never_suppresses(self):
        record = _record(scope=ExceptionScope.GLOBAL)
        registry = ExceptionRegistry([record])
        detector = DestructionDetector(exception_registry=registry)
        outcome = detector.detect(_destructive_burst())
        # the finding survives: recognition annotates, it never drops
        assert len(outcome.findings) == 1
        annotated = outcome.context_annotations[0]
        assert record.exception_id in {
            exc.exception_id for exc in annotated.exceptions
        }


# ---------------------------------------------------------------------- #
# Audit-log integrity
# ---------------------------------------------------------------------- #


class TestAuditIntegrity:
    def test_injected_logger_captures_the_full_run(self):
        logger = AuditLogger()
        detector = DestructionDetector(audit_logger=logger)
        assert detector._audit is logger
        detector.detect(_destructive_burst())
        actions = [entry.action.value for entry in logger.entries]
        for expected in (
            "detection_run",
            "finding_emitted",
            "validation_done",
            "context_annotated",
        ):
            assert expected in actions

    def test_audit_log_is_append_only(self):
        logger = AuditLogger()
        snapshot = logger.entries
        logger.log(AuditAction.DETECTION_RUN, {})
        logger.log(AuditAction.FINDING_EMITTED, {})
        # the caller's snapshot is unaffected — entries is a copy
        assert len(snapshot) == 0
        assert len(logger.entries) == 2
        for mutator in (
            "remove", "delete", "clear", "pop", "discard", "truncate",
        ):
            assert not hasattr(logger, mutator)

    def test_audit_entries_are_immutable(self):
        logger = AuditLogger()
        entry = logger.log(AuditAction.DETECTION_RUN, {})
        with pytest.raises(ValidationError):
            entry.action = AuditAction.FINDING_EMITTED  # type: ignore[misc]

    def test_entry_ids_are_sequential_and_unique(self):
        logger = AuditLogger()
        for _ in range(4):
            logger.log(AuditAction.DETECTION_RUN, {})
        ids = [entry.entry_id for entry in logger.entries]
        assert ids == [
            f"audit-{index:08d}" for index in range(1, len(ids) + 1)
        ]


# ---------------------------------------------------------------------- #
# Neutral labeling and explainability grounding
# ---------------------------------------------------------------------- #


class TestNeutralLabeling:
    def test_finding_label_is_neutral(self):
        assert FINDING_LABEL == "Potential cloud destructive activity"
        assert "ransomware" not in FINDING_LABEL.lower()
        assert "confirmed" not in FINDING_LABEL.lower()

    def test_categories_come_from_the_allowed_set(self):
        allowed = {
            category.value
            for category in DestructiveBehaviorCategory
        }
        outcome = DestructionDetector().detect(_destructive_burst())
        for categories in outcome.categories:
            assert set(categories) <= allowed
            assert categories

    def test_machine_readable_block_matches_spec_shape(self):
        outcome = DestructionDetector().detect(_destructive_burst())
        block = outcome.explanations[0].to_dict()
        for key in (
            "top_contributors",
            "supporting_evidence",
            "contradicting_evidence",
            "baseline_quality",
            "telemetry_completeness",
            "model_agreement",
        ):
            assert key in block
        for key in (
            "top_contributors",
            "supporting_evidence",
            "contradicting_evidence",
        ):
            assert all(isinstance(item, str) for item in block[key])
        assert block["telemetry_completeness"] in (
            "HIGH", "MODERATE", "LOW",
        )
        assert block["baseline_quality"] in (
            "GOOD", "LIMITED", "INSUFFICIENT", "NONE",
        )

    def test_contributors_come_from_detector_signals_only(self):
        """No signals -> no contributors: an LLM can rephrase the
        block, but it cannot invent evidence the detector lacked."""
        outcome = DestructionDetector().detect(_destructive_burst())
        finding = outcome.findings[0]
        session = outcome.sessions[0]
        vector = outcome.feature_vectors[0]
        confidence = outcome.confidences[0]
        events = _destructive_burst()
        silent_risk = replace(outcome.risks[0], contributions={})
        explanation = build_explanation(
            finding, session, vector, silent_risk, confidence, events,
        )
        # zero scored signals -> zero contributors (nothing invented);
        # observed session facts may still be reported as evidence
        assert explanation.top_contributors == []
        assert explanation.supporting_evidence
        assert all(
            isinstance(item, str) and item
            for item in explanation.supporting_evidence
        )
