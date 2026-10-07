"""Aegivion Threat-Correlation integration — **Part 5**.

Threat Correlation lives *outside* every algorithm package. This
module is the integration seam for Algorithm #3: destructive-
activity findings flow in one-way and can be annotated with
correlation context originating from other algorithms
(credential compromise, data exfiltration).

Independence by construction:

- this package imports **nothing** from ``detection.*`` or
  ``ingestion.*`` — findings are read through their public
  attributes only (duck typing), so Algorithm #3 never
  depends on it and it never depends on Algorithm #1/#2;
- the broker performs **no cloud actions** — it is a ledger,
  not an actor;
- findings are **immutable** inside correlation: risk,
  confidence and severity are captured once at submission
  and can never be raised or lowered by context.

Design rules enforced here:

1. **One-way flow.** A finding enters via :meth:`submit`;
   nothing ever calls back into a detector.
2. **Context is additive metadata.** Correlation context is
   attached alongside a finding — it never mutates the
   finding's own scores or severity.
3. **Idempotent submission.** The correlation id is a content
   digest of the finding's identity + version stamps, so
   resubmitting the same finding returns the same record.
4. **Nothing is fabricated.** Context for an unknown finding
   id is rejected (``None``) rather than creating a record
   out of thin air.
5. **Audit-complete.** Every submission and context attachment
   is timestamped; acknowledgement is explicit
   (:meth:`acknowledge` / :meth:`pending_review`).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CorrelationContext",
    "CorrelationRecord",
    "ThreatCorrelationBroker",
    "finding_digest",
]


def _finding_field(finding: Any, name: str, default: Any = None) -> Any:
    """Read a public attribute from a duck-typed finding."""
    value = getattr(finding, name, None)
    return default if value is None else value


def _enum_string(value: Any) -> str:
    """Serialize an enum-valued field without importing its package."""
    if value is None:
        return ""
    return str(getattr(value, "value", value))


def finding_digest(finding: Any) -> str:
    """Content digest of a finding's identity + version stamps.

    Two findings with the same id, detector and model lineage
    produce the same digest — regardless of the Python objects
    they were built from.
    """
    identity = {
        "finding_id": _finding_field(finding, "finding_id"),
        "session_id": _finding_field(finding, "session_id"),
        "detector_name": _finding_field(finding, "detector_name"),
        "model_name": _finding_field(finding, "model_name"),
        "model_version": _finding_field(finding, "model_version"),
        "feature_version": _finding_field(finding, "feature_version"),
        "baseline_version": _finding_field(finding, "baseline_version"),
        "scoring_version": _finding_field(finding, "scoring_version"),
        "rule_version": _finding_field(finding, "rule_version"),
    }
    payload = json.dumps(identity, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CorrelationContext(BaseModel):
    """Correlation context attached by another algorithm or feed.

    ``source_algorithm`` is a free-form identifier (e.g.
    ``"aegivion.credential-compromise"``) — naming it is not
    an import and creates no dependency.
    """

    model_config = ConfigDict(frozen=True)

    source_algorithm: str
    context_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    source_version: Optional[str] = None
    received_at: Optional[datetime] = None

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "source_algorithm": self.source_algorithm,
            "context_type": self.context_type,
            "payload": self.payload,
            "source_version": self.source_version,
            "received_at": (
                self.received_at.isoformat() if self.received_at else None
            ),
        }


class CorrelationRecord(BaseModel):
    """A finding as seen by Threat Correlation (audit-complete)."""

    correlation_id: str
    finding_id: str
    session_id: Optional[str]
    detector_name: str
    severity: str
    risk_score: float
    confidence_score: float
    actor_id: Optional[str]
    account_id: Optional[str]
    observed_at: Optional[str]
    versions: dict[str, Any] = Field(default_factory=dict)
    resources_touched: tuple[str, ...] = ()
    submitted_at: datetime
    source_detectors: tuple[str, ...] = ()
    contexts: list[CorrelationContext] = Field(default_factory=list)
    acknowledged: bool = False

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "finding_id": self.finding_id,
            "session_id": self.session_id,
            "detector_name": self.detector_name,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence_score": self.confidence_score,
            "actor_id": self.actor_id,
            "account_id": self.account_id,
            "observed_at": self.observed_at,
            "versions": self.versions,
            "resources_touched": list(self.resources_touched),
            "submitted_at": self.submitted_at.isoformat(),
            "source_detectors": list(self.source_detectors),
            "contexts": [c.to_log_dict() for c in self.contexts],
            "acknowledged": self.acknowledged,
        }


class ThreatCorrelationBroker:
    """One-way integration seam between Algorithm #3 and Threat Correlation.

    Usage::

        broker = ThreatCorrelationBroker()
        record = broker.submit(finding)            # idempotent
        broker.attach_context(                     # additive only
            finding.finding_id,
            CorrelationContext(
                source_algorithm="aegivion.credential-compromise",
                context_type="actor_match",
                payload={"confidence": 0.91},
            ),
        )
        pending = broker.pending_review()
    """

    def __init__(
        self,
        *,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._records: dict[str, CorrelationRecord] = {}
        self._by_finding: dict[str, str] = {}
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------ #
    # Ingest (one-way)
    # ------------------------------------------------------------------ #

    def submit(self, finding: Any) -> CorrelationRecord:
        """Submit a finding; returns its correlation record.

        Idempotent: resubmitting the same finding (same identity
        digest) returns the existing record unchanged.
        """
        finding_id = _finding_field(finding, "finding_id")
        digest = finding_digest(finding)
        existing = self._by_finding.get(finding_id)
        if existing is not None and self._records[existing].correlation_id == digest:
            return self._records[existing]

        versions = {
            "model_name": _finding_field(finding, "model_name"),
            "model_version": _finding_field(finding, "model_version"),
            "feature_version": _finding_field(finding, "feature_version"),
            "baseline_version": _finding_field(finding, "baseline_version"),
            "scoring_version": _finding_field(finding, "scoring_version"),
            "rule_version": _finding_field(finding, "rule_version"),
            "confidence_version": _finding_field(finding, "confidence_version"),
            "severity_version": _finding_field(finding, "severity_version"),
        }
        detector_name = _finding_field(finding, "detector_name") or "unknown"
        observed_at = _finding_field(finding, "observed_at")
        resources = _finding_field(finding, "resources_touched") or ()
        record = CorrelationRecord(
            correlation_id=digest,
            finding_id=finding_id,
            session_id=_finding_field(finding, "session_id"),
            detector_name=detector_name,
            severity=_enum_string(_finding_field(finding, "severity")),
            risk_score=float(_finding_field(finding, "risk_score", 0.0)),
            confidence_score=float(
                _finding_field(finding, "confidence_score", 0.0)
            ),
            actor_id=_finding_field(finding, "actor_id"),
            account_id=_finding_field(finding, "account_id"),
            observed_at=(
                observed_at.isoformat()
                if isinstance(observed_at, datetime)
                else (str(observed_at) if observed_at is not None else None)
            ),
            versions=versions,
            resources_touched=tuple(resources),
            submitted_at=self._clock(),
            source_detectors=(detector_name,),
        )
        self._records[digest] = record
        self._by_finding[finding_id] = digest
        return record

    def submit_many(
        self, findings: Sequence[Any]
    ) -> list[CorrelationRecord]:
        """Submit a batch of findings (order preserved, idempotent)."""
        return [self.submit(finding) for finding in findings]

    # ------------------------------------------------------------------ #
    # Correlation context (additive only)
    # ------------------------------------------------------------------ #

    def attach_context(
        self,
        finding_id: str,
        context: CorrelationContext,
    ) -> Optional[CorrelationRecord]:
        """Attach correlation context to a submitted finding.

        Context is metadata: the record's risk, confidence and
        severity are untouched. Unknown finding ids return
        ``None`` — no record is fabricated.
        """
        digest = self._by_finding.get(finding_id)
        if digest is None:
            return None
        record = self._records[digest]
        attached = context.model_copy(deep=True)
        if attached.received_at is None:
            # Frozen model: stamp via copy-with-update, never mutation.
            attached = attached.model_copy(
                update={"received_at": self._clock()}
            )
        record.contexts.append(attached)
        return record

    # ------------------------------------------------------------------ #
    # Ledger views
    # ------------------------------------------------------------------ #

    def get(self, finding_id: str) -> Optional[CorrelationRecord]:
        digest = self._by_finding.get(finding_id)
        return self._records.get(digest) if digest is not None else None

    def records(self) -> list[CorrelationRecord]:
        """All correlation records in submission order."""
        return list(self._records.values())

    def pending_review(self) -> list[CorrelationRecord]:
        """Records that have not been acknowledged yet."""
        return [r for r in self._records.values() if not r.acknowledged]

    def acknowledge(self, correlation_id: str) -> bool:
        """Mark a record acknowledged; ``False`` when unknown."""
        record = self._records.get(correlation_id)
        if record is None:
            return False
        record.acknowledged = True
        return True

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "record_count": len(self._records),
            "pending_review": len(self.pending_review()),
            "records": [r.to_log_dict() for r in self._records.values()],
        }
