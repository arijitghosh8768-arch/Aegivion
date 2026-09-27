"""Tamper-evident audit logging - **Part 3 (ARDE)**.

Suppression decisions, ARDE validations and finding state changes must be
auditable: an adversary who can suppress alerts must not be able to suppress
them *silently*. This module provides a minimal append-only log with a hash
chain: each entry commits to the previous entry's digest, so any later edit
or deletion breaks the chain and is detectable via ``verify()``.

The chain is not a substitute for external WORM storage; it makes casual
tampering detectable inside the same datastore.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class AuditEntry:
    """One immutable audit record."""

    seq: int
    timestamp: datetime
    actor: str
    action: str
    subject: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "subject": self.subject,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


class AuditLog:
    """In-memory append-only log with hash chaining.

    Swap for a persistent sink by wrapping ``append``; the chaining contract
    (``prev_hash`` + canonical JSON) is what matters for verifiability.
    """

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def append(
        self,
        *,
        actor: str,
        action: str,
        subject: str,
        payload: Optional[dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
    ) -> AuditEntry:
        ts = timestamp or datetime.now(timezone.utc)
        prev_hash = self._entries[-1].entry_hash if self._entries else self.GENESIS
        seq = len(self._entries)
        body = _canonical(
            {
                "seq": seq,
                "timestamp": ts.isoformat(),
                "actor": actor,
                "action": action,
                "subject": subject,
                "payload": payload or {},
                "prev_hash": prev_hash,
            }
        )
        entry_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        entry = AuditEntry(
            seq=seq,
            timestamp=ts,
            actor=actor,
            action=action,
            subject=subject,
            payload=dict(payload or {}),
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    # -- reads ----------------------------------------------------------- #

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def find(
        self,
        *,
        action: Optional[str] = None,
        subject: Optional[str] = None,
    ) -> list[AuditEntry]:
        return [
            entry
            for entry in self._entries
            if (action is None or entry.action == action)
            and (subject is None or entry.subject == subject)
        ]

    def verify(self) -> tuple[bool, Optional[int]]:
        """Verify the hash chain. Returns ``(ok, first_broken_seq)``."""
        prev = self.GENESIS
        for entry in self._entries:
            body = _canonical(
                {
                    "seq": entry.seq,
                    "timestamp": entry.timestamp.isoformat(),
                    "actor": entry.actor,
                    "action": entry.action,
                    "subject": entry.subject,
                    "payload": entry.payload,
                    "prev_hash": entry.prev_hash,
                }
            )
            if entry.prev_hash != prev:
                return False, entry.seq
            if hashlib.sha256(body.encode("utf-8")).hexdigest() != entry.entry_hash:
                return False, entry.seq
            prev = entry.entry_hash
        return True, None

    def __len__(self) -> int:
        return len(self._entries)


__all__ = ["AuditEntry", "AuditLog"]
