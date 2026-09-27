"""Session construction.

Every event is assigned to an :class:`IdentitySession`. Sessions matter because a
single event may look harmless while a *sequence* from one context
(login -> AssumeRole -> IAM change -> CreateAccessKey) does not.

A session is keyed by the resolved principal plus the provider session id when
one exists. When no explicit session id is available (e.g. IAM user API calls)
the tracker falls back to a continuity rule: a new session starts when the
identity goes idle beyond ``idle_timeout_minutes``, when the session exceeds
``max_duration_hours``, or when its context changes (IP / country / user agent).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from .config import SessionConfig
from .exceptions import SessionBuildError
from .schemas import (
    BaselineCategory,
    CloudProvider,
    IdentityActivityEvent,
    IdentitySession,
)


class SessionDecision(BaseModel):
    """Outcome of feeding one event into the tracker."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_key: str
    is_new_session: bool
    break_reason: Optional[str] = None
    closed_session: Optional[IdentitySession] = None
    session: IdentitySession


class SessionBuilder:
    """Builds and maintains :class:`IdentitySession` objects."""

    def __init__(self, config: Optional[SessionConfig] = None) -> None:
        self.config = config or SessionConfig()

    # ------------------------------------------------------------------ #
    # Key derivation
    # ------------------------------------------------------------------ #

    @staticmethod
    def session_key(event: IdentityActivityEvent) -> str:
        """Deterministic session key for an event.

        Prefers the provider's own session identity (assumed-role session ARN,
        access key ID) so distinct sessions are never merged.
        """
        identity = event.identity_key or event.principal_id
        discriminator = event.session_id or event.access_key_id
        if discriminator:
            return f"{identity}#{discriminator}"
        return f"{identity}#{SessionBuilder._context_fingerprint(event)}"

    @staticmethod
    def _context_fingerprint(event: IdentityActivityEvent) -> str:
        parts = [event.source_ip or "noip", event.user_agent or "noua"]
        return "|".join(parts)

    # ------------------------------------------------------------------ #
    # Session creation / continuation
    # ------------------------------------------------------------------ #

    def create(self, event: IdentityActivityEvent) -> IdentitySession:
        """Start a fresh session from the given event."""
        key = self.session_key(event)
        return IdentitySession(
            session_key=key,
            identity_key=event.identity_key or event.principal_id,
            provider=event.provider,
            account_id=event.account_id,
            principal_id=event.principal_id,
            principal_name=event.principal_name,
            baseline_category=event.baseline_category,
            start_time=event.timestamp,
            last_seen=event.timestamp,
            source_ip=event.source_ip,
            country=event.country,
            asn=event.asn,
            user_agent=event.user_agent,
            region=event.region,
            event_count=1,
            unique_services=1,
            privilege_changes=1 if event.privilege_change else 0,
            api_count=1,
            event_ids=[event.event_id],
        )

    def append(self, session: IdentitySession, event: IdentityActivityEvent) -> IdentitySession:
        """Return a copy of ``session`` with ``event`` folded in."""
        if event.timestamp < session.start_time:
            raise SessionBuildError(
                "cannot append an event older than the session start",
                context={"session": session.session_key, "event": event.event_id},
            )
        # Service cardinality is tracked by the SessionTracker, which owns the
        # per-session service set; ``append`` only folds in the event itself.
        updated = session.model_copy(
            update={
                "last_seen": event.timestamp,
                "event_count": session.event_count + 1,
                "api_count": session.api_count + 1,
                "privilege_changes": session.privilege_changes
                + (1 if event.privilege_change else 0),
                "event_ids": [*session.event_ids, event.event_id],
                "region": session.region or event.region,
            }
        )
        return updated

    # ------------------------------------------------------------------ #
    # Continuity rules
    # ------------------------------------------------------------------ #

    def should_start_new_session(
        self, session: IdentitySession, event: IdentityActivityEvent
    ) -> Optional[str]:
        """Return a break reason, or ``None`` to continue the session."""
        if (event.identity_key or event.principal_id) != session.identity_key:
            return "identity_changed"

        gap = event.timestamp - session.last_seen
        if gap < timedelta(0):
            return "out_of_order_timestamp"
        if gap > timedelta(minutes=self.config.idle_timeout_minutes):
            return "idle_timeout"
        if (event.timestamp - session.start_time) > timedelta(
            hours=self.config.max_duration_hours
        ):
            return "max_duration_exceeded"

        if self.config.break_on_context_change:
            for field in self.config.context_change_fields:
                previous = getattr(session, field, None)
                current = getattr(event, field, None)
                if previous is not None and current is not None and previous != current:
                    return f"context_change:{field}"
        return None


class SessionTracker:
    """Streaming tracker that maintains one open session per identity."""

    def __init__(self, config: Optional[SessionConfig] = None) -> None:
        self.builder = SessionBuilder(config)
        self._open: dict[str, IdentitySession] = {}
        self._services: dict[str, set[str]] = {}

    def open_sessions(self) -> list[IdentitySession]:
        return list(self._open.values())

    def close(self, identity_key: str) -> Optional[IdentitySession]:
        session = self._open.pop(identity_key, None)
        self._services.pop(identity_key, None)
        return session

    def add_event(self, event: IdentityActivityEvent) -> SessionDecision:
        """Feed one event and return the resulting session decision."""
        identity = event.identity_key or event.principal_id
        current = self._open.get(identity)
        reason: Optional[str] = None

        if current is None:
            reason = "no_open_session"
        else:
            reason = self.builder.should_start_new_session(current, event)

        closed: Optional[IdentitySession] = None
        if current is None or reason is not None:
            if current is not None:
                closed = self._finalize(identity)
            session = self.builder.create(event)
            self._open[identity] = session
            self._services[identity] = {event.service_name}
            is_new = True
        else:
            session = self.builder.append(current, event)
            self._open[identity] = session
            self._services.setdefault(identity, set()).add(event.service_name)
            is_new = False

        session = session.model_copy(
            update={"unique_services": len(self._services.get(identity, set()))}
        )
        self._open[identity] = session

        return SessionDecision(
            session_key=session.session_key,
            is_new_session=is_new,
            break_reason=reason if is_new else None,
            closed_session=closed,
            session=session,
        )

    def _finalize(self, identity_key: str) -> Optional[IdentitySession]:
        session = self._open.pop(identity_key, None)
        self._services.pop(identity_key, None)
        return session


__all__ = ["SessionBuilder", "SessionDecision", "SessionTracker"]
