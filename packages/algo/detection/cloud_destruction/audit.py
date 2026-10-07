"""Audit logging — **Part 6**.

The detector keeps an append-only record of what it
*did* — and it only ever observes: emits findings, runs
validation, annotates context. Every entry is versioned
(:data:`AUDIT_VERSION`) and deterministic: timestamps
are injected by the caller (``clock``), so replay
comparisons stay reproducible.

Actions logged:

- ``detection_run``    — one ``detect()`` invocation
- ``finding_emitted``  — one finding + its categories
- ``validation_done``  — one ARDE validation report
- ``context_annotated``— legitimate-activity annotation
- ``exception_stored`` — exception record lifecycle

The logger never deletes entries and never mutates
findings; remediation actions belong to the separate
Aegivion response module and are **not** logged here
as detector capabilities.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

from algo.detection.cloud_destruction.registry import AUDIT_VERSION

__all__ = ["AuditAction", "AuditEntry", "AuditLogger"]


class AuditAction(str, Enum):
    """Auditable detector actions."""

    DETECTION_RUN = "detection_run"
    FINDING_EMITTED = "finding_emitted"
    VALIDATION_DONE = "validation_done"
    CONTEXT_ANNOTATED = "context_annotated"
    EXCEPTION_STORED = "exception_stored"


class AuditEntry(BaseModel):
    """One append-only audit record."""

    model_config = ConfigDict(frozen=True)

    entry_id: str
    timestamp: Optional[datetime] = None
    audit_version: str = AUDIT_VERSION
    action: AuditAction
    detail: dict[str, Any] = Field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat()
            if self.timestamp
            else None,
            "audit_version": self.audit_version,
            "action": self.action.value,
            "detail": self.detail,
        }


class AuditLogger:
    """Append-only, in-memory audit log.

    Deterministic by construction: entries carry a
    timestamp only when a ``clock`` is injected (tests
    and replay passes inject a fixed one).
    """

    def __init__(
        self,
        *,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._entries: list[AuditEntry] = []
        self._clock = clock
        self._counter = 0

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def _next_id(self) -> str:
        self._counter += 1
        return f"audit-{self._counter:08d}"

    def log(self, action: AuditAction, detail: dict[str, Any]) -> AuditEntry:
        """Append one entry; returns it."""
        entry = AuditEntry(
            entry_id=self._next_id(),
            timestamp=self._clock() if self._clock else None,
            action=action,
            detail=dict(detail),
        )
        self._entries.append(entry)
        return entry

    def log_detection_run(
        self, event_count: int, session_count: int
    ) -> AuditEntry:
        return self.log(
            AuditAction.DETECTION_RUN,
            {"event_count": event_count, "session_count": session_count},
        )

    def log_finding(
        self,
        finding_id: str,
        session_id: str,
        *,
        severity: str,
        risk_score: float,
        confidence_score: float,
        categories: tuple[str, ...] = (),
    ) -> AuditEntry:
        return self.log(
            AuditAction.FINDING_EMITTED,
            {
                "finding_id": finding_id,
                "session_id": session_id,
                "severity": severity,
                "risk_score": risk_score,
                "confidence_score": confidence_score,
                "categories": list(categories),
            },
        )

    def log_validation(self, report: Any) -> AuditEntry:
        return self.log(
            AuditAction.VALIDATION_DONE,
            {
                "finding_id": report.finding_id,
                "session_id": report.session_id,
                "overall": (
                    report.overall.value
                    if hasattr(report.overall, "value")
                    else str(report.overall)
                ),
                "failed_checks": list(report.failed_checks),
                "warning_count": len(report.warnings),
            },
        )

    def log_context(self, annotation: Any) -> AuditEntry:
        return self.log(
            AuditAction.CONTEXT_ANNOTATED,
            {
                "finding_id": annotation.finding_id,
                "session_id": annotation.session_id,
                "has_context": annotation.has_context,
                "pattern_count": len(annotation.recognized_patterns),
                "exception_count": len(annotation.exceptions),
            },
        )

    def log_exception(self, record: Any) -> AuditEntry:
        return self.log(
            AuditAction.EXCEPTION_STORED,
            {"exception": record.to_log_dict()},
        )

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "audit_version": AUDIT_VERSION,
            "entry_count": len(self._entries),
            "entries": [entry.to_log_dict() for entry in self._entries],
        }

    def __len__(self) -> int:
        return len(self._entries)


def utc_now() -> datetime:
    """Wall-clock default (injected explicitly for determinism)."""
    return datetime.now(timezone.utc)
