"""SQLAlchemy models for the Cloud Credential Compromise detector.

Tables
------
``identity_profiles``     one row per identity x baseline window
``identity_events``       normalized events (access keys stored as fingerprints)
``identity_sessions``     session aggregates
``behavioral_features``   per-event feature vectors (written in Part 2)
``security_findings``     the shared Aegivion findings table
``baseline_versions``     immutable baseline snapshots for audit/reproducibility

Portability: JSON columns use JSONB on PostgreSQL and JSON elsewhere, so the
same models run under SQLite in tests.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from detection.credential_compromise.schemas import utcnow

from .database import Base

#: JSONB on PostgreSQL, plain JSON everywhere else.
JsonType = JSON().with_variant(JSONB(), "postgresql")


def _uuid() -> str:
    return str(uuid.uuid4())


class IdentityProfileRow(Base):
    __tablename__ = "identity_profiles"
    __table_args__ = (
        UniqueConstraint("identity_key", "window_days", name="uq_identity_profile_window"),
        Index("ix_identity_profiles_category", "provider", "account_id", "baseline_category"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)

    identity_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(16), nullable=False, default="aws")
    account_id: Mapped[str | None] = mapped_column(String(64))
    principal_id: Mapped[str] = mapped_column(String(512), nullable=False)
    principal_name: Mapped[str | None] = mapped_column(String(255))
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False, default="Unknown")
    identity_kind: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    baseline_category: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    role_arn: Mapped[str | None] = mapped_column(String(512))
    department: Mapped[str | None] = mapped_column(String(128))
    team: Mapped[str | None] = mapped_column(String(128))

    window_days: Mapped[int] = mapped_column(Integer, nullable=False)

    observation_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observation_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    normal_hours: Mapped[dict] = mapped_column(JsonType, default=dict)
    normal_days: Mapped[dict] = mapped_column(JsonType, default=dict)
    normal_countries: Mapped[dict] = mapped_column(JsonType, default=dict)
    normal_asns: Mapped[dict] = mapped_column(JsonType, default=dict)
    normal_ip_ranges: Mapped[dict] = mapped_column(JsonType, default=dict)
    normal_user_agents: Mapped[dict] = mapped_column(JsonType, default=dict)
    normal_regions: Mapped[dict] = mapped_column(JsonType, default=dict)
    normal_services: Mapped[dict] = mapped_column(JsonType, default=dict)
    normal_api_families: Mapped[dict] = mapped_column(JsonType, default=dict)
    normal_role_assumptions: Mapped[dict] = mapped_column(JsonType, default=dict)

    avg_events_per_hour: Mapped[float] = mapped_column(Float, default=0.0)
    std_events_per_hour: Mapped[float] = mapped_column(Float, default=0.0)
    read_write_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    normal_privilege_level: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    mfa_expected: Mapped[bool] = mapped_column(Boolean, default=False)

    baseline_quality: Mapped[str] = mapped_column(String(16), default="COLD_START")
    baseline_version: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class IdentityEventRow(Base):
    __tablename__ = "identity_events"
    __table_args__ = (
        Index("ix_identity_events_lookup", "identity_key", "timestamp"),
        Index("ix_identity_events_session", "session_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    identity_key: Mapped[str] = mapped_column(String(512), nullable=False)
    session_key: Mapped[str | None] = mapped_column(String(640))

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    provider: Mapped[str] = mapped_column(String(16), default="aws")
    account_id: Mapped[str | None] = mapped_column(String(64))
    region: Mapped[str | None] = mapped_column(String(64))
    region_hint: Mapped[str | None] = mapped_column(String(128))

    principal_id: Mapped[str] = mapped_column(String(512), nullable=False)
    principal_name: Mapped[str | None] = mapped_column(String(255))
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    identity_kind: Mapped[str] = mapped_column(String(16), default="unknown")
    baseline_category: Mapped[str] = mapped_column(String(32), default="unknown")

    # Never store credential material: only a salted fingerprint + masked form.
    access_key_fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    access_key_masked: Mapped[str | None] = mapped_column(String(64))
    role_arn: Mapped[str | None] = mapped_column(String(512))

    event_source: Mapped[str] = mapped_column(String(255), nullable=False)
    event_name: Mapped[str] = mapped_column(String(255), nullable=False)
    event_category: Mapped[str] = mapped_column(String(16), default="unknown")
    service_name: Mapped[str] = mapped_column(String(64), nullable=False)
    api_family: Mapped[str] = mapped_column(String(64), default="DEFAULT_API", index=True)
    read_or_write: Mapped[str] = mapped_column(String(16), default="unknown")
    privilege_change: Mapped[bool] = mapped_column(Boolean, default=False)

    source_ip: Mapped[str | None] = mapped_column(String(64))
    country: Mapped[str | None] = mapped_column(String(8))
    asn: Mapped[int | None] = mapped_column(Integer)
    user_agent: Mapped[str | None] = mapped_column(Text)
    mfa_authenticated: Mapped[bool | None] = mapped_column(Boolean)
    session_creation_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    request_rate_context: Mapped[float | None] = mapped_column(Float)
    raw_event_reference: Mapped[str | None] = mapped_column(String(1024))
    normalization_warnings: Mapped[list] = mapped_column(JsonType, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class IdentitySessionRow(Base):
    __tablename__ = "identity_sessions"
    __table_args__ = (Index("ix_identity_sessions_identity", "identity_key", "start_time"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_key: Mapped[str] = mapped_column(String(640), nullable=False, unique=True, index=True)
    identity_key: Mapped[str] = mapped_column(String(512), nullable=False)

    provider: Mapped[str] = mapped_column(String(16), default="aws")
    account_id: Mapped[str | None] = mapped_column(String(64))
    principal_id: Mapped[str] = mapped_column(String(512), nullable=False)
    principal_name: Mapped[str | None] = mapped_column(String(255))
    baseline_category: Mapped[str] = mapped_column(String(32), default="unknown")

    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    source_ip: Mapped[str | None] = mapped_column(String(64))
    country: Mapped[str | None] = mapped_column(String(8))
    asn: Mapped[int | None] = mapped_column(Integer)
    user_agent: Mapped[str | None] = mapped_column(Text)
    region: Mapped[str | None] = mapped_column(String(64))

    event_count: Mapped[int] = mapped_column(Integer, default=0)
    unique_services: Mapped[int] = mapped_column(Integer, default=0)
    privilege_changes: Mapped[int] = mapped_column(Integer, default=0)
    api_count: Mapped[int] = mapped_column(Integer, default=0)
    event_ids: Mapped[list] = mapped_column(JsonType, default=list)
    risk_score: Mapped[float | None] = mapped_column(Float)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class BehavioralFeatureRow(Base):
    """Per-event behavioral feature vector (populated by Part 2)."""

    __tablename__ = "behavioral_features"
    __table_args__ = (Index("ix_behavioral_features_event", "event_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    identity_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    session_key: Mapped[str | None] = mapped_column(String(640))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    features: Mapped[dict] = mapped_column(JsonType, default=dict)
    rule_signals: Mapped[dict] = mapped_column(JsonType, default=dict)
    risk_score: Mapped[float | None] = mapped_column(Float)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    baseline_quality: Mapped[str | None] = mapped_column(String(16))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class SecurityFindingRow(Base):
    """Shared Aegivion findings table - reused, not duplicated."""

    __tablename__ = "security_findings"
    __table_args__ = (Index("ix_security_findings_identity", "identity_key", "last_seen"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    identity_key: Mapped[str] = mapped_column(String(512), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), default="aws")
    account_id: Mapped[str | None] = mapped_column(String(64))
    principal_id: Mapped[str] = mapped_column(String(512), nullable=False)
    principal_name: Mapped[str | None] = mapped_column(String(255))

    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    signals: Mapped[list] = mapped_column(JsonType, default=list)
    evidence: Mapped[list] = mapped_column(JsonType, default=list)
    recommended_actions: Mapped[list] = mapped_column(JsonType, default=list)

    session_key: Mapped[str | None] = mapped_column(String(640))
    session_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("identity_sessions.id"))

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    status: Mapped[str] = mapped_column(String(16), default="OPEN")
    arde_status: Mapped[str | None] = mapped_column(String(16))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class BaselineVersionRow(Base):
    """Immutable snapshot of a baseline, for reproducibility and audit."""

    __tablename__ = "baseline_versions"
    __table_args__ = (
        UniqueConstraint("identity_key", "window_days", "version", name="uq_baseline_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    identity_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    window_days: Mapped[int] = mapped_column(Integer, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    baseline_quality: Mapped[str] = mapped_column(String(16), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    span_days: Mapped[float] = mapped_column(Float, default=0.0)
    payload: Mapped[dict] = mapped_column(JsonType, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


__all__ = [
    "BaselineVersionRow",
    "BehavioralFeatureRow",
    "IdentityEventRow",
    "IdentityProfileRow",
    "IdentitySessionRow",
    "JsonType",
    "SecurityFindingRow",
]
