"""Storage layer: SQLAlchemy models + repository for detection state.

Tables (schema designed for later Azure/GCP addition — everything is
provider-neutral):

- data_activity_events            canonical normalized events
- data_access_sessions            built sessions (JSON payload + indexes)
- data_resource_profiles          per-resource observed history
- data_baseline_versions          immutable behavioral baseline versions
- exfiltration_findings           findings (discovery-only in Part 1)

Raw events are NOT duplicated here: ``raw_event_reference`` points into
the raw event store (see raw_store.py).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Float,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session as SASession, mapped_column
from sqlalchemy.pool import StaticPool

from algo.data_exfiltration.data_exfiltration.schemas import (
    DataAccessSession,
    DataActivityEvent,
    DataBaselineVersion,
    DataResourceProfile,
    SecurityFinding,
)


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _dump(model) -> dict[str, Any]:
    """Serialize a pydantic model to a JSON-safe dict."""
    return json.loads(model.model_dump_json())


class DataActivityEventRow(Base):
    __tablename__ = "data_activity_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(16), index=True)
    account_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    region: Mapped[str | None] = mapped_column(String(32), nullable=True)
    event_time_epoch_ms: Mapped[float] = mapped_column(Float, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(256), index=True, nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data_action: Mapped[str | None] = mapped_column(String(32), nullable=True)
    read_or_write: Mapped[str | None] = mapped_column(String(8), nullable=True)
    bucket: Mapped[str | None] = mapped_column(String(256), index=True, nullable=True)
    object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    raw_event_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        Index("ix_dae_actor_time", "actor_id", "event_time_epoch_ms"),
        Index("ix_dae_resource_time", "resource_id", "event_time_epoch_ms"),
    )


class DataAccessSessionRow(Base):
    __tablename__ = "data_access_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(256), index=True, nullable=True)
    provider: Mapped[str] = mapped_column(String(16), index=True)
    start_time_epoch_ms: Mapped[float | None] = mapped_column(Float, index=True, nullable=True)
    end_time_epoch_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_state: Mapped[str] = mapped_column(String(16), default="new")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)


class DataResourceProfileRow(Base):
    __tablename__ = "data_resource_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    resource_id: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sensitivity_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    history_event_count: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(default=_utcnow, onupdate=_utcnow)


class DataBaselineVersionRow(Base):
    __tablename__ = "data_baseline_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at_epoch_ms: Mapped[float] = mapped_column(Float)
    session_count: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)


class ExfiltrationFindingRow(Base):
    __tablename__ = "exfiltration_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    detector_name: Mapped[str] = mapped_column(String(128), index=True)
    finding_type: Mapped[str] = mapped_column(String(32), default="data_discovery")
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    observed_at_epoch_ms: Mapped[float] = mapped_column(Float, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(256), index=True, nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)


class DetectionRepository:
    """Facade over the storage schema. One repository per pipeline run."""

    def __init__(self, url: str = "sqlite:///:memory:") -> None:
        if url.endswith(":memory:"):
            # share one in-memory DB across connections so a single
            # repository instance sees its own writes
            self._engine = create_engine(
                url,
                future=True,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        else:
            self._engine = create_engine(url, future=True)
        Base.metadata.create_all(self._engine)

    # -- events ------------------------------------------------------------

    def save_events(self, events: list[DataActivityEvent]) -> int:
        with SASession(self._engine) as db, db.begin():
            for event in events:
                db.merge(DataActivityEventRow(
                    event_id=event.event_id,
                    provider=event.provider.value,
                    account_id=event.account_id,
                    region=event.region,
                    event_time_epoch_ms=event.event_time_epoch_ms,
                    actor_id=event.actor_id,
                    resource_id=event.resource_id,
                    resource_type=event.resource_type,
                    data_action=event.data_action.value,
                    read_or_write=event.read_or_write.value,
                    bucket=event.bucket,
                    object_key=event.object_key,
                    raw_event_reference=event.raw_event_reference,
                    payload=_dump(event),
                ))
        return len(events)

    def list_events(self, limit: int = 1000) -> list[DataActivityEvent]:
        with SASession(self._engine) as db:
            rows = db.scalars(select(DataActivityEventRow).limit(limit)).all()
            return [DataActivityEvent.model_validate(row.payload) for row in rows]

    # -- sessions ------------------------------------------------------------

    def save_sessions(self, sessions: list[DataAccessSession]) -> int:
        with SASession(self._engine) as db, db.begin():
            for session in sessions:
                db.merge(DataAccessSessionRow(
                    session_id=session.session_id,
                    actor_id=session.actor_id,
                    provider=session.provider.value,
                    start_time_epoch_ms=session.start_time_epoch_ms,
                    end_time_epoch_ms=session.end_time_epoch_ms,
                    event_count=session.event_count,
                    risk_state=session.risk_state.value,
                    payload=_dump(session),
                ))
        return len(sessions)

    def list_sessions(self, limit: int = 1000) -> list[DataAccessSession]:
        with SASession(self._engine) as db:
            rows = db.scalars(select(DataAccessSessionRow).limit(limit)).all()
            return [DataAccessSession.model_validate(row.payload) for row in rows]

    # -- resource profiles -----------------------------------------------------

    def save_resource_profile(self, profile: DataResourceProfile) -> None:
        with SASession(self._engine) as db, db.begin():
            db.merge(DataResourceProfileRow(
                resource_id=profile.resource_id,
                resource_type=profile.resource_type,
                sensitivity_level=profile.sensitivity_level.value if profile.sensitivity_level else None,
                history_event_count=profile.history_event_count,
                payload=_dump(profile),
            ))

    def get_resource_profile(self, resource_id: str) -> DataResourceProfile | None:
        with SASession(self._engine) as db:
            row = db.scalars(
                select(DataResourceProfileRow).where(DataResourceProfileRow.resource_id == resource_id)
            ).first()
            return DataResourceProfile.model_validate(row.payload) if row else None

    # -- baselines ------------------------------------------------------------

    def save_baseline(self, baseline: DataBaselineVersion) -> None:
        with SASession(self._engine) as db, db.begin():
            db.merge(DataBaselineVersionRow(
                version_id=baseline.version_id,
                created_at_epoch_ms=baseline.created_at_epoch_ms,
                session_count=baseline.session_count,
                payload=_dump(baseline),
            ))

    def get_baseline(self, version_id: str) -> DataBaselineVersion | None:
        with SASession(self._engine) as db:
            row = db.scalars(
                select(DataBaselineVersionRow).where(DataBaselineVersionRow.version_id == version_id)
            ).first()
            return DataBaselineVersion.model_validate(row.payload) if row else None

    # -- findings ------------------------------------------------------------

    def save_finding(self, finding: SecurityFinding) -> None:
        with SASession(self._engine) as db, db.begin():
            db.merge(ExfiltrationFindingRow(
                finding_id=finding.finding_id,
                detector_name=finding.detector_name,
                finding_type=finding.finding_type.value,
                severity=finding.severity.value if finding.severity else None,
                observed_at_epoch_ms=finding.observed_at_epoch_ms,
                actor_id=finding.actor_id,
                resource_id=finding.resource_id,
                session_id=finding.session_id,
                payload=_dump(finding),
            ))

    def list_findings(self, limit: int = 1000) -> list[SecurityFinding]:
        with SASession(self._engine) as db:
            rows = db.scalars(select(ExfiltrationFindingRow).limit(limit)).all()
            return [SecurityFinding.model_validate(row.payload) for row in rows]
