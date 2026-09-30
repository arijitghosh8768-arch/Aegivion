"""Repository for identity profiles and baseline versions.

Implements the :class:`ProfileRepositoryProtocol` used by
``detection.credential_compromise.profile.ProfileService``, so cold-start peer
lookups are a storage concern, not a detection concern.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from algo.detection.credential_compromise.profile import PeerCriteria
from algo.detection.credential_compromise.schemas import (
    BaselineCategory,
    BaselineQuality,
    CloudProvider,
    IdentityKind,
    IdentityProfile,
    PrincipalType,
)

from .models import BaselineVersionRow, IdentityProfileRow

#: Distribution columns copied verbatim between domain object and row.
_DISTRIBUTION_FIELDS = (
    "normal_hours",
    "normal_days",
    "normal_countries",
    "normal_asns",
    "normal_ip_ranges",
    "normal_user_agents",
    "normal_regions",
    "normal_services",
    "normal_api_families",
    "normal_role_assumptions",
)

_SCALAR_FIELDS = (
    "provider",
    "account_id",
    "principal_id",
    "principal_name",
    "principal_type",
    "identity_kind",
    "baseline_category",
    "role_arn",
    "department",
    "team",
    "observation_start",
    "observation_end",
    "event_count",
    "distinct_days",
    "avg_events_per_hour",
    "std_events_per_hour",
    "read_write_ratio",
    "normal_privilege_level",
    "mfa_expected",
    "baseline_quality",
)
# NOTE: ``baseline_version`` is deliberately excluded - it is managed by
# :meth:`SqlIdentityProfileRepository.upsert_profile` so it always increments.


class SqlIdentityProfileRepository:
    """SQLAlchemy-backed profile store."""

    def __init__(self, session: OrmSession, *, peer_limit: int = 50) -> None:
        self.session = session
        self.peer_limit = peer_limit

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    def get_profile(
        self, identity_key: str, window_days: int
    ) -> Optional[IdentityProfile]:
        row = self.session.execute(
            select(IdentityProfileRow).where(
                IdentityProfileRow.identity_key == identity_key,
                IdentityProfileRow.window_days == window_days,
            )
        ).scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    def list_profiles(
        self,
        *,
        provider: Optional[CloudProvider] = None,
        baseline_category: Optional[BaselineCategory] = None,
        window_days: Optional[int] = None,
        limit: int = 500,
    ) -> list[IdentityProfile]:
        statement = select(IdentityProfileRow)
        if provider is not None:
            statement = statement.where(IdentityProfileRow.provider == provider.value)
        if baseline_category is not None:
            statement = statement.where(
                IdentityProfileRow.baseline_category == baseline_category.value
            )
        if window_days is not None:
            statement = statement.where(IdentityProfileRow.window_days == window_days)
        statement = statement.order_by(IdentityProfileRow.event_count.desc()).limit(limit)
        return [_to_domain(row) for row in self.session.execute(statement).scalars()]

    def find_peer_profiles(
        self,
        *,
        criteria: PeerCriteria,
        window_days: int,
        exclude_identity_key: Optional[str] = None,
    ) -> list[IdentityProfile]:
        """Find comparable identities for a cold-start baseline.

        Peers must share the baseline category (never mix humans with machines)
        and must themselves have a non-cold-start baseline.
        """
        statement = select(IdentityProfileRow).where(
            IdentityProfileRow.baseline_category == criteria.baseline_category.value,
            IdentityProfileRow.window_days == window_days,
            IdentityProfileRow.baseline_quality != BaselineQuality.COLD_START.value,
        )
        if criteria.account_id:
            statement = statement.where(IdentityProfileRow.account_id == criteria.account_id)
        # Prefer the tightest available match, then relax.
        for column, value in (
            (IdentityProfileRow.role_arn, criteria.role_arn),
            (IdentityProfileRow.department, criteria.department),
            (IdentityProfileRow.team, criteria.team),
        ):
            if value:
                statement = statement.where(column == value)
        if exclude_identity_key:
            statement = statement.where(IdentityProfileRow.identity_key != exclude_identity_key)
        statement = statement.order_by(IdentityProfileRow.event_count.desc()).limit(self.peer_limit)
        return [_to_domain(row) for row in self.session.execute(statement).scalars()]

    def count_peers(
        self,
        *,
        criteria: PeerCriteria,
        window_days: int,
        exclude_identity_key: Optional[str] = None,
    ) -> int:
        return len(
            self.find_peer_profiles(
                criteria=criteria,
                window_days=window_days,
                exclude_identity_key=exclude_identity_key,
            )
        )

    # ------------------------------------------------------------------ #
    # Writes
    # ------------------------------------------------------------------ #

    def upsert_profile(self, profile: IdentityProfile) -> IdentityProfile:
        """Insert or update a profile, incrementing its baseline version."""
        row = self.session.execute(
            select(IdentityProfileRow).where(
                IdentityProfileRow.identity_key == profile.identity_key,
                IdentityProfileRow.window_days == profile.window_days,
            )
        ).scalar_one_or_none()

        if row is None:
            row = IdentityProfileRow(
                identity_key=profile.identity_key,
                window_days=profile.window_days,
                baseline_version=profile.baseline_version or 1,
                **_row_values(profile),
            )
            self.session.add(row)
        else:
            for key, value in _row_values(profile).items():
                setattr(row, key, value)
            row.baseline_version = max(1, (row.baseline_version or 0) + 1)

        self.session.flush()
        return _to_domain(row)

    def record_baseline_version(
        self,
        profile: IdentityProfile,
        *,
        span_days: float = 0.0,
        payload: Optional[dict[str, Any]] = None,
    ) -> BaselineVersionRow:
        """Persist an immutable baseline snapshot and deactivate prior ones."""
        existing = self.session.execute(
            select(BaselineVersionRow).where(
                BaselineVersionRow.identity_key == profile.identity_key,
                BaselineVersionRow.window_days == profile.window_days,
                BaselineVersionRow.is_active.is_(True),
            )
        ).scalars().all()
        for row in existing:
            row.is_active = False

        version_row = BaselineVersionRow(
            identity_key=profile.identity_key,
            window_days=profile.window_days,
            version=profile.baseline_version,
            baseline_quality=profile.baseline_quality.value,
            event_count=profile.event_count,
            span_days=span_days,
            payload=payload if payload is not None else _to_domain_payload(profile),
            is_active=True,
        )
        self.session.add(version_row)
        self.session.flush()
        return version_row

    def get_active_baseline_version(
        self, identity_key: str, window_days: int
    ) -> Optional[BaselineVersionRow]:
        return self.session.execute(
            select(BaselineVersionRow).where(
                BaselineVersionRow.identity_key == identity_key,
                BaselineVersionRow.window_days == window_days,
                BaselineVersionRow.is_active.is_(True),
            )
        ).scalar_one_or_none()

    def delete_profile(self, identity_key: str, window_days: int) -> bool:
        row = self.session.execute(
            select(IdentityProfileRow).where(
                IdentityProfileRow.identity_key == identity_key,
                IdentityProfileRow.window_days == window_days,
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        self.session.delete(row)
        self.session.flush()
        return True


# --------------------------------------------------------------------------- #
# Mapping helpers
# --------------------------------------------------------------------------- #


def _row_values(profile: IdentityProfile) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for field in _SCALAR_FIELDS:
        raw = getattr(profile, field)
        if isinstance(raw, (CloudProvider, PrincipalType, IdentityKind, BaselineCategory, BaselineQuality)):
            values[field] = raw.value
        else:
            values[field] = raw
    for field in _DISTRIBUTION_FIELDS:
        values[field] = dict(getattr(profile, field) or {})
    return values


def _to_domain_payload(profile: IdentityProfile) -> dict[str, Any]:
    payload = _row_values(profile)
    payload["baseline_version"] = profile.baseline_version
    for key, value in list(payload.items()):
        if hasattr(value, "isoformat"):
            payload[key] = value.isoformat()
    return payload


def _to_domain(row: IdentityProfileRow) -> IdentityProfile:
    return IdentityProfile(
        identity_key=row.identity_key,
        provider=CloudProvider(row.provider),
        account_id=row.account_id,
        principal_id=row.principal_id,
        principal_name=row.principal_name,
        principal_type=PrincipalType(row.principal_type),
        identity_kind=IdentityKind(row.identity_kind),
        baseline_category=BaselineCategory(row.baseline_category),
        role_arn=row.role_arn,
        department=row.department,
        team=row.team,
        window_days=row.window_days,
        observation_start=row.observation_start,
        observation_end=row.observation_end,
        event_count=row.event_count or 0,
        distinct_days=row.distinct_days or 0,
        normal_hours=dict(row.normal_hours or {}),
        normal_days=dict(row.normal_days or {}),
        normal_countries=dict(row.normal_countries or {}),
        normal_asns=dict(row.normal_asns or {}),
        normal_ip_ranges=dict(row.normal_ip_ranges or {}),
        normal_user_agents=dict(row.normal_user_agents or {}),
        normal_regions=dict(row.normal_regions or {}),
        normal_services=dict(row.normal_services or {}),
        normal_api_families=dict(row.normal_api_families or {}),
        normal_role_assumptions=dict(row.normal_role_assumptions or {}),
        avg_events_per_hour=row.avg_events_per_hour or 0.0,
        std_events_per_hour=row.std_events_per_hour or 0.0,
        read_write_ratio=row.read_write_ratio or 0.0,
        normal_privilege_level=row.normal_privilege_level or "UNKNOWN",
        mfa_expected=bool(row.mfa_expected),
        baseline_quality=BaselineQuality(row.baseline_quality),
        baseline_version=row.baseline_version or 0,
        updated_at=row.updated_at,
    )


__all__ = ["SqlIdentityProfileRepository"]
