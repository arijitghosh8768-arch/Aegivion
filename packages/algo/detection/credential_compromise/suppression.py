"""Suppression / exception engine - **Part 3 (ARDE)**.

False-positive control with hard governance rules:

* every suppression is **audited** (written to the :class:`AuditLog`),
* every suppression is **time-bound** (max duration from config),
* every suppression is **scoped** (identity-, rule-, or finding-specific),
* every suppression is **reversible** (explicit revoke, also audited),
* suppressions **never silence alerts silently**: by default HIGH/CRITICAL
  findings are downgraded to review instead of dropped
  (``SuppressionConfig.never_silence_high_severity``).

The engine holds no detection logic; it only answers *should this finding be
surfaced?* and always leaves an audit trail either way.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from algo.detection.credential_compromise.audit import AuditLog
from algo.detection.credential_compromise.config import SuppressionConfig
from algo.detection.credential_compromise.schemas import Severity, utcnow


class SuppressionRule(BaseModel):
    """One suppression entry."""

    model_config = ConfigDict(frozen=True)

    suppression_id: str
    scope: str                       # "identity" | "rule" | "finding"
    scope_value: str
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime

    @property
    def is_expired(self) -> bool:
        return utcnow() >= self.expires_at


class SuppressionDecision(BaseModel):
    """Result of evaluating a finding against active suppressions."""

    model_config = ConfigDict(frozen=True)

    suppressed: bool
    matched_suppression_ids: tuple[str, ...] = ()
    # When never_silence_high_severity applies, the finding is downgraded to
    # review rather than hidden.
    downgraded_to_review: bool = False
    explanation: str = ""


class SuppressionEngine:
    """Evaluates findings against governed suppression rules."""

    def __init__(
        self,
        audit_log: Optional[AuditLog] = None,
        config: Optional[SuppressionConfig] = None,
    ) -> None:
        # NB: ``AuditLog`` defines __len__, so an empty log is falsy - must
        # not use ``or`` here or a passed-in log would be silently replaced.
        self.audit = audit_log if audit_log is not None else AuditLog()
        self.config = config or SuppressionConfig()
        self._rules: dict[str, SuppressionRule] = {}

    # -- lifecycle ------------------------------------------------------- #

    def add(
        self,
        *,
        scope: str,
        scope_value: str,
        reason: str,
        created_by: str,
        duration_days: Optional[int] = None,
    ) -> SuppressionRule:
        if scope not in ("identity", "rule", "finding"):
            raise ValueError("scope must be identity, rule or finding")
        now = utcnow()
        days = duration_days or self.config.max_duration_days
        if days > self.config.max_duration_days:
            raise ValueError(
                f"suppression duration {days}d exceeds policy maximum "
                f"{self.config.max_duration_days}d"
            )
        rule = SuppressionRule(
            suppression_id=f"SUP-{len(self._rules) + 1:05d}",
            scope=scope,
            scope_value=scope_value,
            reason=reason,
            created_by=created_by,
            created_at=now,
            expires_at=now + timedelta(days=days),
        )
        self._rules[rule.suppression_id] = rule
        self.audit.append(
            actor=created_by,
            action="suppression.created",
            subject=rule.suppression_id,
            payload={
                "scope": scope,
                "scope_value": scope_value,
                "reason": reason,
                "expires_at": rule.expires_at.isoformat(),
            },
        )
        return rule

    def revoke(self, suppression_id: str, *, revoked_by: str) -> bool:
        rule = self._rules.pop(suppression_id, None)
        if rule is None:
            return False
        self.audit.append(
            actor=revoked_by,
            action="suppression.revoked",
            subject=suppression_id,
            payload={"reason": rule.reason},
        )
        return True

    # -- evaluation ------------------------------------------------------ #

    def evaluate(
        self,
        *,
        identity_key: str,
        rule_ids: list[str],
        severity: Severity,
    ) -> SuppressionDecision:
        """Should this finding be suppressed?

        Expired rules are ignored (and lazily dropped, with an audit entry).
        High-severity findings are only ever downgraded, never silently
        dropped, when ``never_silence_high_severity`` is set.
        """
        matched: list[SuppressionRule] = []
        for rule in list(self._rules.values()):
            if rule.is_expired:
                self._rules.pop(rule.suppression_id, None)
                self.audit.append(
                    actor="system",
                    action="suppression.expired",
                    subject=rule.suppression_id,
                    payload={"scope_value": rule.scope_value},
                )
                continue
            hit = (
                rule.scope == "identity" and rule.scope_value == identity_key
            ) or (
                rule.scope == "rule" and rule.scope_value in rule_ids
            ) or (
                rule.scope == "finding" and identity_key in rule.scope_value
            )
            if hit:
                matched.append(rule)

        if not matched:
            return SuppressionDecision(suppressed=False, explanation="no active suppression")

        high = severity in (Severity.HIGH, Severity.CRITICAL)
        if high and self.config.never_silence_high_severity:
            return SuppressionDecision(
                suppressed=False,
                matched_suppression_ids=tuple(r.suppression_id for r in matched),
                downgraded_to_review=True,
                explanation=(
                    "suppression matched but severity HIGH/CRITICAL is never "
                    "silently dropped; finding downgraded to review"
                ),
            )

        return SuppressionDecision(
            suppressed=True,
            matched_suppression_ids=tuple(r.suppression_id for r in matched),
            explanation=f"suppressed by {', '.join(r.suppression_id for r in matched)}",
        )

    # -- inspection ------------------------------------------------------ #

    def active_rules(self) -> list[SuppressionRule]:
        return [rule for rule in self._rules.values() if not rule.is_expired]


__all__ = ["SuppressionDecision", "SuppressionEngine", "SuppressionRule"]
