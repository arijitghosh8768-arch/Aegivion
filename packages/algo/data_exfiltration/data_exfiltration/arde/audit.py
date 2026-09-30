"""Audit log: append-only, hash-chained record of every ARDE decision.

Every validation (and every exception evaluation inside it) is logged.
Entries are chained by content hash so tampering is detectable:
entry N's digest covers entry N-1's digest.

The log is evidence, not action: nothing here deletes findings or
touches infrastructure.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

GENESIS_PREVIOUS_HASH = "0" * 12


class AuditEntry(BaseModel):
    """One immutable audit record."""

    entry_id: str
    sequence: int
    timestamp_epoch_ms: float
    actor: str
    """System component that produced the event (e.g. 'arde.validator')."""
    action: str
    """What happened: 'finding_validated', 'profile_registered', ..."""
    finding_id: str | None = None
    session_id: str | None = None
    validation_status: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    """Full decision content: checks summary, exceptions, downgrade."""
    previous_hash: str
    entry_hash: str

    def compute_hash(self) -> str:
        basis = json.dumps(
            {
                "entry_id": self.entry_id,
                "sequence": self.sequence,
                "timestamp_epoch_ms": self.timestamp_epoch_ms,
                "actor": self.actor,
                "action": self.action,
                "finding_id": self.finding_id,
                "session_id": self.session_id,
                "validation_status": self.validation_status,
                "payload": self.payload,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
            default=str,
        ).encode()
        return hashlib.sha256(basis).hexdigest()[:12]


class AuditLog:
    """In-memory append-only audit log with integrity verification."""

    def __init__(self, *, actor: str = "arde.validator") -> None:
        self._entries: list[AuditEntry] = []
        self._actor = actor

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    # ------------------------------------------------------------------

    def append(
        self,
        action: str,
        *,
        finding_id: str | None = None,
        session_id: str | None = None,
        validation_status: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditEntry:
        previous = self._entries[-1].entry_hash if self._entries else GENESIS_PREVIOUS_HASH
        now_ms = datetime.now(timezone.utc).timestamp() * 1000.0
        entry = AuditEntry(
            entry_id=f"aud-{uuid.uuid4().hex[:12]}",
            sequence=len(self._entries),
            timestamp_epoch_ms=now_ms,
            actor=self._actor,
            action=action,
            finding_id=finding_id,
            session_id=session_id,
            validation_status=validation_status,
            payload=payload or {},
            previous_hash=previous,
            entry_hash="",
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        return entry

    def record_validation(
        self,
        outcome: Any,
        *,
        finding: Any = None,
    ) -> AuditEntry:
        """Log one complete validation outcome (called by ARDEValidator)."""
        exceptions = getattr(outcome, "exceptions_applied", []) or []
        matched = [e for e in exceptions if e.get("matched")]
        return self.append(
            "finding_validated",
            finding_id=getattr(outcome, "finding_id", None),
            session_id=getattr(outcome, "session_id", None),
            validation_status=getattr(outcome.validation_status, "value", None),
            payload={
                "robustness_score": getattr(outcome, "robustness_score", None),
                "robustness_level": getattr(
                    getattr(outcome, "robustness_level", None), "value", None
                ),
                "checks": [
                    {
                        "check_name": c.check_name,
                        "status": c.status.value,
                        "severity": c.severity.value,
                        "message": c.message,
                    }
                    for c in getattr(outcome, "checks", [])
                ],
                "exceptions_matched": [
                    {
                        "profile_id": e.get("profile_id"),
                        "profile_name": e.get("profile_name"),
                        "kind": e.get("kind"),
                        "reason": e.get("reason"),
                    }
                    for e in matched
                ],
                "downgrade": getattr(outcome, "downgrade", None),
                "severity_at_validation": (
                    getattr(getattr(finding, "severity", None), "value", None)
                    if finding is not None
                    else None
                ),
            },
        )

    # ------------------------------------------------------------------
    # integrity
    # ------------------------------------------------------------------

    def verify(self) -> bool:
        """Recompute the hash chain; True when untampered."""
        previous = GENESIS_PREVIOUS_HASH
        for entry in self._entries:
            if entry.previous_hash != previous:
                return False
            if entry.entry_hash != entry.compute_hash():
                return False
            previous = entry.entry_hash
        return True

    def entries_for_finding(self, finding_id: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.finding_id == finding_id]

    def to_json(self) -> str:
        return json.dumps(
            [e.model_dump(mode="json") for e in self._entries],
            sort_keys=True,
        )
