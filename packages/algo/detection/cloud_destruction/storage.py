"""Storage layer: SQLAlchemy models + repository for detection state.

Tables (provider-neutral, designed for later Azure/GCP addition):

- resource_activity_events          canonical normalized events
- destructive_activity_sessions     built sessions (JSON payload + indexes)
- resource_protection_profiles      per-resource protection/history
- destruction_findings              reserved for Part 2 (findings land later)

Raw events are NOT duplicated here: ``raw_event_reference`` /
``data_provenance.raw_reference`` point into the raw event store.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from sqlalchemy import (
    JSON,
    Float,
    Index,
    Integer,
    String,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session as SASession, mapped_column
from sqlalchemy.pool import StaticPool

from detection.cloud_destruction.exceptions import DatabaseError
from detection.cloud_destruction.schemas import (
    DestructiveActivitySession,
    ResourceActivityEvent,
    ResourceProtectionProfile,
)


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _dump(model: Any) -> dict[str, Any]:
    """Serialize a pydantic model to a JSON-safe dict."""
    return json.loads(model.model_dump_json())


class ResourceActivityEventRow(Base):
    __tablename__ = "resource_activity_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(16), index=True)
    account_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    event_time_epoch_ms: Mapped[float] = mapped_column(Float, index=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(256), index=True, nullable=True)
    actor_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(512), index=True, nullable=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    resource_arn: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(48), index=True, nullable=True)
    action_category: Mapped[Optional[str]] = mapped_column(String(32), index=True, nullable=True)
    operation_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    object_key: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    snapshot_id: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    recovery_point_id: Mapped[Optional[str]] = mapped_column(String(256), index=True, nullable=True)
    raw_event_reference: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        Index("ix_rae_actor_time", "actor_id", "event_time_epoch_ms"),
        Index("ix_rae_resource_time", "resource_id", "event_time_epoch_ms"),
        Index("ix_rae_category_time", "action_category", "event_time_epoch_ms"),
    )


class DestructiveActivitySessionRow(Base):
    __tablename__ = "destructive_activity_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(256), index=True, nullable=True)
    provider: Mapped[str] = mapped_column(String(16), index=True)
    account_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    start_time_epoch_ms: Mapped[Optional[float]] = mapped_column(Float, index=True, nullable=True)
    end_time_epoch_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    destructive_event_count: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_state: Mapped[str] = mapped_column(String(16), default="new")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)


class ResourceProtectionProfileRow(Base):
    __tablename__ = "resource_protection_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    resource_id: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    business_criticality: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    backup_enabled: Mapped[Optional[bool]] = mapped_column(nullable=True)
    versioning_enabled: Mapped[Optional[bool]] = mapped_column(nullable=True)
    history_event_count: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(default=_utcnow, onupdate=_utcnow)


class DestructionFindingRow(Base):
    """Persisted detection finding (with explanation + contract payload)."""

    __tablename__ = "destruction_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    detector_name: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    observed_at_epoch_ms: Mapped[float] = mapped_column(Float, index=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(256), index=True, nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(512), index=True, nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=_utcnow)


class DestructionRepository:
    """Facade over the storage schema. One repository per pipeline run."""

    def __init__(self, url: str = "sqlite:///:memory:") -> None:
        try:
            if url.endswith(":memory:"):
                # Share one in-memory DB across connections so a single
                # repository instance sees its own writes.
                self._engine = create_engine(
                    url,
                    future=True,
                    connect_args={"check_same_thread": False},
                    poolclass=StaticPool,
                )
            else:
                self._engine = create_engine(url, future=True)
            Base.metadata.create_all(self._engine)
        except Exception as exc:  # pragma: no cover - defensive
            raise DatabaseError(f"cannot open repository at {url!r}", context={"cause": str(exc)}) from exc

    # -- events --------------------------------------------------------------

    def save_events(self, events: Sequence[ResourceActivityEvent]) -> int:
        rows = []
        for event in events:
            rows.append(
                ResourceActivityEventRow(
                    event_id=event.event_id,
                    provider=event.provider.value,
                    account_id=event.account_id,
                    region=event.region,
                    event_time_epoch_ms=event.timestamp.timestamp() * 1000.0,
                    actor_id=event.actor_id,
                    actor_type=event.actor_type.value,
                    resource_id=event.resource_id,
                    resource_type=event.resource_type.value,
                    resource_arn=event.resource_arn,
                    action=event.action,
                    action_category=event.action_category.value,
                    operation_type=event.operation_type.value,
                    object_key=event.object_key,
                    snapshot_id=event.snapshot_id,
                    recovery_point_id=event.recovery_point_id,
                    raw_event_reference=event.raw_event_reference,
                    payload=_dump(event),
                )
            )
        with SASession(self._engine) as db, db.begin():
            for row in rows:
                db.merge(row)
        return len(rows)

    def list_events(self, limit: int = 1000) -> list[ResourceActivityEvent]:
        with SASession(self._engine) as db:
            rows = db.scalars(
                select(ResourceActivityEventRow).order_by(ResourceActivityEventRow.event_time_epoch_ms).limit(limit)
            ).all()
            return [ResourceActivityEvent.model_validate(row.payload) for row in rows]

    def get_event(self, event_id: str) -> Optional[ResourceActivityEvent]:
        with SASession(self._engine) as db:
            row = db.scalars(
                select(ResourceActivityEventRow).where(ResourceActivityEventRow.event_id == event_id)
            ).first()
            return ResourceActivityEvent.model_validate(row.payload) if row else None

    def count_events(self) -> int:
        with SASession(self._engine) as db:
            return int(db.scalar(select(func.count(ResourceActivityEventRow.id))) or 0)

    # -- sessions ------------------------------------------------------------

    def save_sessions(self, sessions: Sequence[DestructiveActivitySession]) -> int:
        with SASession(self._engine) as db, db.begin():
            for session in sessions:
                db.merge(
                    DestructiveActivitySessionRow(
                        session_id=session.session_id,
                        actor_id=session.actor_id,
                        provider=session.provider.value,
                        account_id=session.account_id,
                        start_time_epoch_ms=(
                            session.start_time.timestamp() * 1000.0 if session.start_time else None
                        ),
                        end_time_epoch_ms=(
                            session.end_time.timestamp() * 1000.0 if session.end_time else None
                        ),
                        event_count=session.event_count,
                        destructive_event_count=session.destructive_event_count,
                        risk_state=session.risk_state,
                        payload=_dump(session),
                    )
                )
        return len(sessions)

    def list_sessions(self, limit: int = 1000) -> list[DestructiveActivitySession]:
        with SASession(self._engine) as db:
            rows = db.scalars(
                select(DestructiveActivitySessionRow).order_by(DestructiveActivitySessionRow.start_time_epoch_ms).limit(limit)
            ).all()
            return [DestructiveActivitySession.model_validate(row.payload) for row in rows]

    def get_session(self, session_id: str) -> Optional[DestructiveActivitySession]:
        with SASession(self._engine) as db:
            row = db.scalars(
                select(DestructiveActivitySessionRow).where(DestructiveActivitySessionRow.session_id == session_id)
            ).first()
            return DestructiveActivitySession.model_validate(row.payload) if row else None

    # -- resource profiles ------------------------------------------------------

    def save_resource_profiles(self, profiles: Sequence[ResourceProtectionProfile]) -> int:
        with SASession(self._engine) as db, db.begin():
            for profile in profiles:
                db.merge(
                    ResourceProtectionProfileRow(
                        resource_id=profile.resource_id,
                        resource_type=profile.resource_type.value,
                        business_criticality=(
                            profile.business_criticality.value if profile.business_criticality else None
                        ),
                        backup_enabled=profile.backup_enabled,
                        versioning_enabled=profile.versioning_enabled,
                        history_event_count=profile.history_event_count,
                        payload=_dump(profile),
                    )
                )
        return len(profiles)

    def get_resource_profile(self, resource_id: str) -> Optional[ResourceProtectionProfile]:
        with SASession(self._engine) as db:
            row = db.scalars(
                select(ResourceProtectionProfileRow).where(
                    ResourceProtectionProfileRow.resource_id == resource_id
                )
            ).first()
            return ResourceProtectionProfile.model_validate(row.payload) if row else None

    # -- findings -------------------------------------------------------------

    def save_findings(
        self,
        findings: Sequence[Any],
        *,
        explanations: Optional[Sequence[Optional[Any]]] = None,
        contracts: Optional[Sequence[Optional[dict[str, Any]]]] = None,
    ) -> int:
        """Persist findings; optional explanation/contract payloads ride along.

        ``findings`` are :class:`~detection.cloud_destruction.finding.DestructionFinding`
        objects; ``explanations`` (parallel list, may contain ``None``) are
        :class:`~detection.cloud_destruction.explainability.Explanation` objects and
        ``contracts`` (parallel list, may contain ``None``) are the final finding
        contract dicts produced by
        :mod:`detection.cloud_destruction.contract`.
        """
        payloads: list[dict[str, Any]] = []
        for index, finding in enumerate(findings):
            payload: dict[str, Any] = json.loads(
                json.dumps(_finding_payload(finding), default=str)
            )
            if explanations is not None and index < len(explanations) and explanations[index] is not None:
                payload["explanation"] = explanations[index].to_dict()
            if contracts is not None and index < len(contracts) and contracts[index] is not None:
                payload["contract"] = contracts[index]
            payloads.append(payload)
        with SASession(self._engine) as db, db.begin():
            for finding, payload in zip(findings, payloads):
                db.merge(
                    DestructionFindingRow(
                        finding_id=finding.finding_id,
                        detector_name=finding.detector_name,
                        severity=(
                            finding.severity.value if finding.severity else None
                        ),
                        observed_at_epoch_ms=(
                            finding.observed_at.timestamp() * 1000.0
                            if finding.observed_at
                            else 0.0
                        ),
                        actor_id=finding.actor_id,
                        resource_id=(
                            finding.resources_touched[0]
                            if finding.resources_touched
                            else None
                        ),
                        session_id=finding.session_id,
                        payload=payload,
                    )
                )
        return len(findings)

    def list_findings(self, limit: int = 1000) -> list[Any]:
        """List persisted findings (DestructionFinding objects)."""
        with SASession(self._engine) as db:
            rows = db.scalars(
                select(DestructionFindingRow).order_by(
                    DestructionFindingRow.observed_at_epoch_ms
                ).limit(limit)
            ).all()
            return [_finding_from_payload(row.payload) for row in rows]

    def get_finding(self, finding_id: str) -> Optional[Any]:
        """Fetch one finding (DestructionFinding) by id."""
        payload = self.get_finding_payload(finding_id)
        return _finding_from_payload(payload) if payload else None

    def get_finding_payload(self, finding_id: str) -> Optional[dict[str, Any]]:
        """Fetch the full persisted payload (incl. explanation + contract)."""
        with SASession(self._engine) as db:
            row = db.scalars(
                select(DestructionFindingRow).where(
                    DestructionFindingRow.finding_id == finding_id
                )
            ).first()
            return dict(row.payload) if row else None


def _finding_payload(finding: Any) -> dict[str, Any]:
    """Serialize a DestructionFinding to a JSON-safe dict."""
    data = finding.to_log_dict()
    data["raw"] = dict(finding.raw)
    data["missing_evidence"] = list(finding.missing_evidence)
    return data


def _finding_from_payload(payload: dict[str, Any]) -> Any:
    """Rebuild a DestructionFinding from its persisted payload."""
    from detection.cloud_destruction.finding import DestructionFinding, Severity

    versions = payload.get("versions") or {}
    return DestructionFinding(
        finding_id=payload["finding_id"],
        session_id=payload["session_id"],
        detector_name=payload.get("detector_name", "aegivion.cloud_destruction"),
        severity=Severity(payload.get("severity", "low")),
        risk_score=float(payload.get("risk_score", 0.0)),
        confidence_score=float(payload.get("confidence_score", 0.0)),
        actor_id=payload.get("actor_id"),
        account_id=payload.get("account_id"),
        observed_at=(
            datetime.fromisoformat(payload["observed_at"])
            if payload.get("observed_at")
            else None
        ),
        model_name=versions.get("model_name", "unknown"),
        model_version=versions.get("model_version", "0"),
        feature_version=versions.get("feature_version", "0"),
        baseline_version=versions.get("baseline_version"),
        scoring_version=versions.get("scoring_version", "0"),
        rule_version=versions.get("rule_version", "0"),
        confidence_version=versions.get("confidence_version", "0"),
        severity_version=versions.get("severity_version", "0"),
        risk_contributions=dict(payload.get("risk_contributions") or {}),
        confidence_factors=dict(payload.get("confidence_factors") or {}),
        missing_evidence=tuple(payload.get("missing_evidence") or ()),
        approved_activity=payload.get("approved_activity"),
        event_ids=tuple(payload.get("event_ids") or ()),
        resources_touched=tuple(payload.get("resources_touched") or ()),
        raw=dict(payload.get("raw") or {}),
    )


__all__ = [
    "Base",
    "DestructionFindingRow",
    "DestructionRepository",
    "DestructiveActivitySessionRow",
    "ResourceActivityEventRow",
    "ResourceProtectionProfileRow",
]
