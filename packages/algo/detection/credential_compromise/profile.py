"""Identity profile lifecycle: quality grading and cold-start fallback.

A profile is *the answer to "what does normal look like for this identity?"*.
This module owns:

* **Baseline quality grading** - how much the detector should trust a profile.
  Quality is derived from real sample counts and coverage, never guessed.
* **Cold start** - a brand-new identity must not be treated as suspicious just
  because it has no history. It falls back to a *peer* baseline.
* **Peer selection** - same baseline category, account, and (where available)
  role, team or department.

Aggregating raw events into the ``normal_*`` distributions is
``baseline.py`` (Part 2); this module supplies and validates the profile
container those aggregations populate.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from .config import BaselineConfig
from .schemas import (
    BaselineCategory,
    BaselineQuality,
    CloudProvider,
    IdentityActivityEvent,
    IdentityKind,
    IdentityProfile,
    PrincipalType,
    ensure_utc,
)

# --------------------------------------------------------------------------- #
# Quality grading
# --------------------------------------------------------------------------- #


def assess_baseline_quality(
    *,
    event_count: int,
    span_days: float,
    distinct_days: int,
    config: BaselineConfig,
) -> BaselineQuality:
    """Grade a baseline from real observation statistics.

    A baseline is only EXCELLENT/GOOD when it has *both* enough samples and
    enough time coverage - a burst of 5,000 events in one hour is not a good
    model of a human's week.
    """
    if event_count < config.min_events_for_personal_baseline:
        return BaselineQuality.COLD_START

    if (
        event_count >= config.min_events_excellent
        and span_days >= config.min_span_days_excellent
        and distinct_days >= config.min_span_days_excellent
    ):
        return BaselineQuality.EXCELLENT

    if (
        event_count >= config.min_events_good
        and span_days >= config.min_span_days_good
        and distinct_days >= config.min_distinct_days_good
    ):
        return BaselineQuality.GOOD

    if (
        event_count >= config.min_events_limited
        and span_days >= config.min_span_days_limited
        and distinct_days >= config.min_distinct_days_limited
    ):
        return BaselineQuality.LIMITED

    return BaselineQuality.COLD_START


def observation_stats(events: Sequence[IdentityActivityEvent]) -> tuple[float, int]:
    """Return ``(span_days, distinct_days)`` for a set of identity events."""
    if not events:
        return 0.0, 0
    timestamps = [ensure_utc(e.timestamp) for e in events]
    start, end = min(timestamps), max(timestamps)
    span_days = (end - start).total_seconds() / 86400.0
    distinct_days = len({ts.date() for ts in timestamps})
    return span_days, distinct_days


# --------------------------------------------------------------------------- #
# Profile construction (container only - distributions arrive in Part 2)
# --------------------------------------------------------------------------- #


def initial_profile(
    *,
    identity_key: str,
    principal_id: str,
    window_days: int,
    provider: CloudProvider = CloudProvider.AWS,
    account_id: Optional[str] = None,
    principal_name: Optional[str] = None,
    principal_type: PrincipalType = PrincipalType.UNKNOWN,
    identity_kind: IdentityKind = IdentityKind.UNKNOWN,
    baseline_category: BaselineCategory = BaselineCategory.UNKNOWN,
    role_arn: Optional[str] = None,
    department: Optional[str] = None,
    team: Optional[str] = None,
) -> IdentityProfile:
    """Create an empty, explicitly cold-start profile for an identity.

    No distributions are invented here - an empty profile is honest about
    knowing nothing yet.
    """
    return IdentityProfile(
        identity_key=identity_key,
        provider=provider,
        account_id=account_id,
        principal_id=principal_id,
        principal_name=principal_name,
        principal_type=principal_type,
        identity_kind=identity_kind,
        baseline_category=baseline_category,
        role_arn=role_arn,
        department=department,
        team=team,
        window_days=window_days,
        event_count=0,
        distinct_days=0,
        baseline_quality=BaselineQuality.COLD_START,
        baseline_version=0,
    )


def apply_observation_stats(
    profile: IdentityProfile,
    *,
    event_count: int,
    span_days: float,
    distinct_days: int,
    config: BaselineConfig,
    observation_start: Optional[datetime] = None,
    observation_end: Optional[datetime] = None,
) -> IdentityProfile:
    """Update a profile's sample statistics and re-grade its quality."""
    quality = assess_baseline_quality(
        event_count=event_count,
        span_days=span_days,
        distinct_days=distinct_days,
        config=config,
    )
    return profile.model_copy(
        update={
            "event_count": event_count,
            "distinct_days": distinct_days,
            "baseline_quality": quality,
            "observation_start": ensure_utc(observation_start) if observation_start else None,
            "observation_end": ensure_utc(observation_end) if observation_end else None,
        }
    )


# --------------------------------------------------------------------------- #
# Cold-start / peer fallback
# --------------------------------------------------------------------------- #


class PeerCriteria(BaseModel):
    """Criteria used to find comparable identities for a cold-start baseline."""

    model_config = ConfigDict(frozen=True)

    baseline_category: BaselineCategory
    account_id: Optional[str] = None
    role_arn: Optional[str] = None
    department: Optional[str] = None
    team: Optional[str] = None
    require_same_category: bool = True

    def describe(self) -> list[str]:
        labels: list[str] = [f"category={self.baseline_category.value}"]
        for name in ("account_id", "role_arn", "department", "team"):
            value = getattr(self, name)
            if value:
                labels.append(f"{name}={value}")
        return labels


class BaselineSelection(BaseModel):
    """The baseline the detector will actually compare an event against."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    identity_key: str
    window_days: int
    quality: BaselineQuality
    is_peer_baseline: bool = False
    profile: Optional[IdentityProfile] = None
    peer_profiles: list[IdentityProfile] = Field(default_factory=list)
    peer_count: int = 0
    reason: str = ""

    @property
    def is_cold_start(self) -> bool:
        return self.quality is BaselineQuality.COLD_START

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"BaselineSelection(identity_key={self.identity_key!r}, "
            f"quality={self.quality.value}, peers={self.peer_count})"
        )


class ProfileService:
    """Coordinates personal vs peer baseline selection.

    The repository is injected so this logic is unit-testable without a
    database; see ``storage/identity_repository.py``.
    """

    def __init__(
        self,
        repository: "ProfileRepositoryProtocol",
        config: Optional[BaselineConfig] = None,
    ) -> None:
        self.repository = repository
        self.config = config or BaselineConfig()

    def peer_criteria(self, profile: IdentityProfile) -> PeerCriteria:
        return PeerCriteria(
            baseline_category=profile.baseline_category,
            account_id=profile.account_id,
            role_arn=profile.role_arn,
            department=profile.department,
            team=profile.team,
        )

    def select_baseline(
        self,
        *,
        identity_key: str,
        window_days: int,
        peer_criteria: Optional[PeerCriteria] = None,
    ) -> BaselineSelection:
        """Choose the personal baseline if trustworthy, else a peer baseline."""
        personal = self.repository.get_profile(identity_key, window_days)

        if personal is not None and personal.baseline_quality in (
            BaselineQuality.EXCELLENT,
            BaselineQuality.GOOD,
            BaselineQuality.LIMITED,
        ):
            return BaselineSelection(
                identity_key=identity_key,
                window_days=window_days,
                quality=personal.baseline_quality,
                is_peer_baseline=False,
                profile=personal,
                reason="personal_baseline",
            )

        if peer_criteria is None and personal is not None:
            peer_criteria = self.peer_criteria(personal)

        peers: list[IdentityProfile] = []
        if peer_criteria is not None:
            peers = self.repository.find_peer_profiles(
                criteria=peer_criteria,
                window_days=window_days,
                exclude_identity_key=identity_key,
            )

        if personal is None:
            quality = BaselineQuality.COLD_START
            reason = "no_personal_baseline"
        else:
            quality = personal.baseline_quality
            reason = "personal_baseline_insufficient"

        final_reason = f"{reason}_with_peer_fallback" if peers else reason

        return BaselineSelection(
            identity_key=identity_key,
            window_days=window_days,
            quality=quality,
            is_peer_baseline=bool(peers),
            profile=personal,
            peer_profiles=peers,
            peer_count=len(peers),
            reason=final_reason,
        )


class ProfileRepositoryProtocol:
    """Structural type for the profile repository used by :class:`ProfileService`."""

    def get_profile(self, identity_key: str, window_days: int) -> Optional[IdentityProfile]:
        raise NotImplementedError

    def find_peer_profiles(
        self,
        *,
        criteria: PeerCriteria,
        window_days: int,
        exclude_identity_key: Optional[str] = None,
    ) -> list[IdentityProfile]:
        raise NotImplementedError


__all__ = [
    "BaselineSelection",
    "PeerCriteria",
    "ProfileRepositoryProtocol",
    "ProfileService",
    "apply_observation_stats",
    "assess_baseline_quality",
    "initial_profile",
    "observation_stats",
]
