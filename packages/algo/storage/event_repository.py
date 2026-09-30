"""Repository for normalized identity events and sessions.

Access keys are **never** persisted. The repository stores a salted SHA-256
fingerprint plus a masked display form, which is all behavioural novelty checks
need. A stored event can therefore be reconstructed for analysis while the
credential identifier itself stays recoverable only by its owner.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from algo.detection.credential_compromise.schemas import (
    AccessType,
    BaselineCategory,
    CloudProvider,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    IdentitySession,
    PrincipalType,
    fingerprint_secret,
    mask_secret,
)

from .models import IdentityEventRow, IdentitySessionRow


class SqlEventRepository:
    """SQLAlchemy-backed event/session store."""

    def __init__(self, session: OrmSession, *, secret_salt: str = "") -> None:
        self.session = session
        self.secret_salt = secret_salt

    # ------------------------------------------------------------------ #
    # Events
    # ------------------------------------------------------------------ #

    def save_event(
        self, event: IdentityActivityEvent, *, session_key: Optional[str] = None
    ) -> IdentityEventRow:
        """Persist one event, redacting credential material."""
        existing = self.session.execute(
            select(IdentityEventRow).where(IdentityEventRow.event_id == event.event_id)
        ).scalar_one_or_none()
        if existing is not None:
            return existing

        row = IdentityEventRow(
            event_id=event.event_id,
            identity_key=event.identity_key or event.principal_id,
            session_key=session_key,
            timestamp=event.timestamp,
            provider=event.provider.value,
            account_id=event.account_id,
            region=event.region,
            region_hint=event.region_hint,
            principal_id=event.principal_id,
            principal_name=event.principal_name,
            principal_type=event.principal_type.value,
            identity_kind=event.identity_kind.value,
            baseline_category=event.baseline_category.value,
            access_key_fingerprint=fingerprint_secret(
                event.access_key_id, salt=self.secret_salt
            ),
            access_key_masked=mask_secret(event.access_key_id),
            role_arn=event.role_arn,
            event_source=event.event_source,
            event_name=event.event_name,
            event_category=event.event_category.value,
            service_name=event.service_name,
            api_family=event.api_family,
            read_or_write=event.read_or_write.value,
            privilege_change=event.privilege_change,
            source_ip=event.source_ip,
            country=event.country,
            asn=event.asn,
            user_agent=event.user_agent,
            mfa_authenticated=event.mfa_authenticated,
            session_creation_time=event.session_creation_time,
            request_rate_context=event.request_rate_context,
            raw_event_reference=event.raw_event_reference,
            normalization_warnings=list(event.normalization_warnings),
        )
        self.session.add(row)
        self.session.flush()
        return row

    def save_events(
        self, events: Sequence[IdentityActivityEvent]
    ) -> list[IdentityEventRow]:
        return [self.save_event(event) for event in events]

    def get_event(self, event_id: str) -> Optional[IdentityActivityEvent]:
        row = self.session.execute(
            select(IdentityEventRow).where(IdentityEventRow.event_id == event_id)
        ).scalar_one_or_none()
        return _to_event(row) if row is not None else None

    def recent_events(
        self,
        identity_key: str,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 5000,
    ) -> list[IdentityActivityEvent]:
        """Events for one identity, oldest first - the baseline input."""
        statement = select(IdentityEventRow).where(IdentityEventRow.identity_key == identity_key)
        if since is not None:
            statement = statement.where(IdentityEventRow.timestamp >= since)
        if until is not None:
            statement = statement.where(IdentityEventRow.timestamp <= until)
        statement = statement.order_by(IdentityEventRow.timestamp.asc()).limit(limit)
        return [_to_event(row) for row in self.session.execute(statement).scalars()]

    def count_events(
        self, identity_key: str, *, since: Optional[datetime] = None
    ) -> int:
        statement = select(func.count(IdentityEventRow.id)).where(
            IdentityEventRow.identity_key == identity_key
        )
        if since is not None:
            statement = statement.where(IdentityEventRow.timestamp >= since)
        return int(self.session.execute(statement).scalar_one())

    def attach_session_key(self, event_id: str, session_key: str) -> bool:
        row = self.session.execute(
            select(IdentityEventRow).where(IdentityEventRow.event_id == event_id)
        ).scalar_one_or_none()
        if row is None:
            return False
        row.session_key = session_key
        self.session.flush()
        return True

    # ------------------------------------------------------------------ #
    # Sessions
    # ------------------------------------------------------------------ #

    def save_session(self, identity_session: IdentitySession) -> IdentitySessionRow:
        row = self.session.execute(
            select(IdentitySessionRow).where(
                IdentitySessionRow.session_key == identity_session.session_key
            )
        ).scalar_one_or_none()

        if row is None:
            row = IdentitySessionRow(session_key=identity_session.session_key)
            self.session.add(row)

        row.identity_key = identity_session.identity_key
        row.provider = identity_session.provider.value
        row.account_id = identity_session.account_id
        row.principal_id = identity_session.principal_id
        row.principal_name = identity_session.principal_name
        row.baseline_category = identity_session.baseline_category.value
        row.start_time = identity_session.start_time
        row.last_seen = identity_session.last_seen
        row.source_ip = identity_session.source_ip
        row.country = identity_session.country
        row.asn = identity_session.asn
        row.user_agent = identity_session.user_agent
        row.region = identity_session.region
        row.event_count = identity_session.event_count
        row.unique_services = identity_session.unique_services
        row.privilege_changes = identity_session.privilege_changes
        row.api_count = identity_session.api_count
        row.event_ids = list(identity_session.event_ids)
        row.risk_score = identity_session.risk_score

        self.session.flush()
        return row

    def get_session(self, session_key: str) -> Optional[IdentitySession]:
        row = self.session.execute(
            select(IdentitySessionRow).where(IdentitySessionRow.session_key == session_key)
        ).scalar_one_or_none()
        return _to_session(row) if row is not None else None

    def list_sessions(
        self,
        identity_key: str,
        *,
        since: Optional[datetime] = None,
        limit: int = 200,
    ) -> list[IdentitySession]:
        statement = select(IdentitySessionRow).where(
            IdentitySessionRow.identity_key == identity_key
        )
        if since is not None:
            statement = statement.where(IdentitySessionRow.start_time >= since)
        statement = statement.order_by(IdentitySessionRow.start_time.desc()).limit(limit)
        return [_to_session(row) for row in self.session.execute(statement).scalars()]


# --------------------------------------------------------------------------- #
# Mapping helpers
# --------------------------------------------------------------------------- #


def _to_event(row: IdentityEventRow) -> IdentityActivityEvent:
    """Rehydrate a stored event.

    ``access_key_id`` and ``session_id`` are intentionally not recoverable from
    storage - behavioural features use the persisted fingerprint instead.
    """
    return IdentityActivityEvent(
        event_id=row.event_id,
        timestamp=row.timestamp,
        provider=CloudProvider(row.provider),
        account_id=row.account_id,
        region=row.region,
        region_hint=row.region_hint,
        principal_id=row.principal_id,
        principal_name=row.principal_name,
        principal_type=PrincipalType(row.principal_type),
        identity_kind=IdentityKind(row.identity_kind),
        baseline_category=BaselineCategory(row.baseline_category),
        identity_key=row.identity_key,
        access_key_id=None,
        role_arn=row.role_arn,
        session_id=None,
        event_source=row.event_source,
        event_name=row.event_name,
        event_category=EventCategory(row.event_category),
        service_name=row.service_name,
        api_family=row.api_family,
        read_or_write=AccessType(row.read_or_write),
        privilege_change=bool(row.privilege_change),
        source_ip=row.source_ip,
        country=row.country,
        asn=row.asn,
        user_agent=row.user_agent,
        mfa_authenticated=row.mfa_authenticated,
        session_creation_time=row.session_creation_time,
        request_rate_context=row.request_rate_context,
        raw_event_reference=row.raw_event_reference,
        normalization_warnings=tuple(row.normalization_warnings or ()),
    )


def _to_session(row: IdentitySessionRow) -> IdentitySession:
    return IdentitySession(
        session_key=row.session_key,
        identity_key=row.identity_key,
        provider=CloudProvider(row.provider),
        account_id=row.account_id,
        principal_id=row.principal_id,
        principal_name=row.principal_name,
        baseline_category=BaselineCategory(row.baseline_category),
        start_time=row.start_time,
        last_seen=row.last_seen,
        source_ip=row.source_ip,
        country=row.country,
        asn=row.asn,
        user_agent=row.user_agent,
        region=row.region,
        event_count=row.event_count or 0,
        unique_services=row.unique_services or 0,
        privilege_changes=row.privilege_changes or 0,
        api_count=row.api_count or 0,
        event_ids=list(row.event_ids or []),
        risk_score=row.risk_score,
    )


__all__ = ["SqlEventRepository"]
