"""Behavioral baseline aggregation - **Part 2**.

This is where stored events become the ``normal_*`` distributions on
:class:`~detection.credential_compromise.schemas.IdentityProfile`.

Two operations are supported:

* **build_profile** - aggregate a batch of historical events into a fresh
  profile for one identity and window.
* **update_profile** - fold a *single new observation* into an existing
  profile with **risk-aware weighting**, the baseline poisoning guard.

Poisoning policy (thresholds from :class:`BaselineConfig`):

======================  =============================================
event risk              effect on the trusted baseline
======================  =============================================
``< limited`` (30)      eligible, full influence (alpha)
``limited..freeze``     eligible, *limited* influence (alpha * factor)
``>= freeze`` (70)      **excluded** - never folded in until reviewed
======================  =============================================

This bounds how fast an attacker can teach the detector: a high-risk
CreateUser followed by attacker-driven activity can never normalize itself.
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone
from typing import Mapping, Optional, Sequence

from detection.credential_compromise.config import BaselineConfig
from detection.credential_compromise.profile import (
    BaselineSelection,
    apply_observation_stats,
)
from detection.credential_compromise.schemas import (
    AccessType,
    BaselineQuality,
    IdentityActivityEvent,
    IdentityProfile,
    ensure_utc,
)

DISTRIBUTION_FIELDS: tuple[str, ...] = (
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

#: Maps a profile field to the event attribute whose value it counts.
_EVENT_KEYS: dict[str, str] = {
    "normal_hours": "hour",          # computed
    "normal_days": "weekday",        # computed
    "normal_countries": "country",
    "normal_asns": "asn",
    "normal_ip_ranges": "ip_range",  # computed (/24 for IPv4)
    "normal_user_agents": "user_agent",
    "normal_regions": "region",
    "normal_services": "service_name",
    "normal_api_families": "api_family",
    "normal_role_assumptions": "role_arn",
}

_PRIVILEGE_LEVELS: tuple[str, ...] = ("NONE", "LOW", "MODERATE", "ELEVATED")


# --------------------------------------------------------------------------- #
# Event keys
# --------------------------------------------------------------------------- #


def hour_key(event: IdentityActivityEvent) -> str:
    """UTC hour-of-day bucket, ``"00"`` .. ``"23"``."""
    return f"{ensure_utc(event.timestamp).hour:02d}"


def weekday_key(event: IdentityActivityEvent) -> str:
    """Python weekday name (Mon..Sun) of the event's UTC timestamp."""
    return ensure_utc(event.timestamp).strftime("%a")


def ip_range_key(event: IdentityActivityEvent) -> str:
    """Coarse network bucket for an event (IPv4 ``/24``).

    IPs are grouped rather than stored per-address so a rotated source IP on
    the same corporate network stays recognizable.
    """
    ip = event.source_ip
    if not ip:
        return "unknown"
    octets = ip.split(".")
    if len(octets) == 4:
        try:
            if all(octet.isdigit() and 0 <= int(octet) <= 255 for octet in octets):
                return ".".join(octets[:3]) + ".0/24"
        except ValueError:  # pragma: no cover - guarded by isdigit
            pass
    return ip


def _event_value(event: IdentityActivityEvent, key: str) -> Optional[str]:
    if key == "hour":
        return hour_key(event)
    if key == "weekday":
        return weekday_key(event)
    if key == "ip_range":
        return ip_range_key(event)
    value = getattr(event, key, None)
    if value is None:
        return None
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #


class _ProfileAccumulator:
    """Collects raw counts for one profile, then renders distributions."""

    def __init__(self) -> None:
        self.counts: dict[str, Counter[str]] = {f: Counter() for f in DISTRIBUTION_FIELDS}
        self.reads = 0
        self.writes = 0
        self.hourly = Counter()
        self.privilege_events = 0
        self.mfa_true = 0
        self.mfa_events = 0
        self.event_count = 0

    def add(self, event: IdentityActivityEvent) -> None:
        self.event_count += 1
        for field, key in _EVENT_KEYS.items():
            value = _event_value(event, key)
            if value is not None:
                self.counts[field][value] += 1
        if event.read_or_write is AccessType.READ:
            self.reads += 1
        elif event.read_or_write is AccessType.WRITE:
            self.writes += 1
        self.hourly[ensure_utc(event.timestamp).hour] += 1
        if event.privilege_change:
            self.privilege_events += 1
        if event.mfa_authenticated is not None:
            self.mfa_events += 1
            if event.mfa_authenticated:
                self.mfa_true += 1

    def merge_counts(self, other: Mapping[str, Mapping[str, float]], weight: float = 1.0) -> None:
        """Blend pre-aggregated distributions into this accumulator."""
        for field, distribution in other.items():
            counter = self.counts[field]
            for value, count in distribution.items():
                counter[str(value)] += float(count) * weight

    @property
    def read_write_ratio(self) -> float:
        if self.writes <= 0:
            return 0.0 if self.reads <= 0 else float("inf")
        return self.reads / self.writes

    def _mean_std_events_per_hour(self) -> tuple[float, float]:
        if self.event_count == 0:
            return 0.0, 0.0
        active_hours = sum(1 for count in self.hourly.values() if count > 0)
        if active_hours == 0:  # pragma: no cover - implies event_count == 0
            return 0.0, 0.0
        counts = [self.hourly[hour] for hour in range(24)]
        total = sum(counts)
        mean_over_all = total / 24.0
        variance = sum((c - mean_over_all) ** 2 for c in counts) / 24.0
        # Scale to an "average active hour" so quiet identities are not
        # punished for hours they are simply not expected to act in.
        mean = total / active_hours
        std = math.sqrt(variance) * (mean / mean_over_all if mean_over_all > 0 else 0.0)
        return mean, std

    def render(self) -> dict[str, object]:
        distributions = {
            field: _normalise(dict(counter))
            for field, counter in self.counts.items()
        }
        mean_per_hour, std_per_hour = self._mean_std_events_per_hour()
        if self.privilege_events > 0:
            share = self.privilege_events / max(1, self.event_count)
            level = "ELEVATED" if share > 0.2 else "MODERATE"
        elif distributions["normal_api_families"].keys() & {
            "IAM_READ",
            "STS_SESSION",
            "S3_MANAGEMENT",
        }:
            level = "LOW"
        else:
            level = "NONE"
        return {
            "distributions": distributions,
            "event_count": self.event_count,
            "read_write_ratio": self.read_write_ratio,
            "avg_events_per_hour": mean_per_hour,
            "std_events_per_hour": std_per_hour,
            "normal_privilege_level": level,
            "mfa_expected": self.mfa_events > 0 and self.mfa_true == self.mfa_events,
        }


def _rendered_to_profile_fields(rendered: Mapping[str, object]) -> dict[str, object]:
    """Flatten a rendered accumulator into ``IdentityProfile`` kwargs."""
    fields: dict[str, object] = {}
    distributions = rendered["distributions"]
    for field in DISTRIBUTION_FIELDS:
        fields[field] = dict(distributions[field])
    for key in (
        "event_count",
        "read_write_ratio",
        "avg_events_per_hour",
        "std_events_per_hour",
        "normal_privilege_level",
        "mfa_expected",
    ):
        fields[key] = rendered[key]
    return fields


def _normalise(values: Mapping[str, float]) -> dict[str, float]:
    """Normalise raw counts to probabilities summing to 1.0.

    ``IdentityProfile`` documents its ``normal_*`` fields as historical
    *frequencies* in ``[0, 1]``; all persisted distributions are normalised.
    """
    total = sum(values.values())
    if total <= 0:
        return {}
    return {key: value / total for key, value in values.items() if value > 0}


def build_profile(
    profile: IdentityProfile,
    events: Sequence[IdentityActivityEvent],
    *,
    config: BaselineConfig,
    observation_start: Optional[datetime] = None,
    observation_end: Optional[datetime] = None,
) -> IdentityProfile:
    """Aggregate historical events into ``profile`` (same identity + window).

    The profile supplies the identity metadata; the events supply the
    distributions. Quality is re-graded from the *observed* sample statistics
    via :func:`profile.apply_observation_stats`.
    """
    if not events:
        raise ValueError("build_profile requires at least one event")

    accumulator = _ProfileAccumulator()
    for event in events:
        accumulator.add(event)

    if observation_start is None:
        observation_start = min(ensure_utc(e.timestamp) for e in events)
    if observation_end is None:
        observation_end = max(ensure_utc(e.timestamp) for e in events)
    span_days = (observation_end - observation_start).total_seconds() / 86400.0
    distinct_days = len({ensure_utc(e.timestamp).date() for e in events})

    updated = profile.model_copy(
        update={
            **_rendered_to_profile_fields(accumulator.render()),
            "observation_start": observation_start,
            "observation_end": observation_end,
        }
    )
    return apply_observation_stats(
        updated,
        event_count=accumulator.event_count,
        span_days=span_days,
        distinct_days=distinct_days,
        config=config,
        observation_start=observation_start,
        observation_end=observation_end,
    )


# --------------------------------------------------------------------------- #
# Risk-aware updates (baseline poisoning protection)
# --------------------------------------------------------------------------- #


def update_policy(
    *,
    event_risk: float,
    config: BaselineConfig,
) -> tuple[str, float]:
    """Classify an observation's eligibility for baseline learning.

    Returns ``(decision, influence_factor)`` where *decision* is one of
    ``"eligible"``, ``"limited_influence"`` or ``"excluded"`` and the factor
    scales the update alpha (0 for excluded).
    """
    if event_risk >= config.baseline_freeze_risk_threshold:
        return "excluded", 0.0
    if event_risk >= config.baseline_limited_influence_risk_threshold:
        return "limited_influence", config.limited_influence_factor
    return "eligible", 1.0


def update_profile(
    profile: IdentityProfile,
    event: IdentityActivityEvent,
    *,
    event_risk: float,
    config: BaselineConfig,
) -> IdentityProfile:
    """Fold one *low-risk* observation into the trusted baseline.

    High-risk observations are refused (poisoning guard); medium-risk ones
    only nudge the distributions. ``baseline_version`` increments on every
    accepted update so behavior changes remain auditable.
    """
    decision, factor = update_policy(event_risk=event_risk, config=config)
    if decision == "excluded" or factor <= 0.0:
        return profile.model_copy(
            update={
                "baseline_version": profile.baseline_version,
                "updated_at": datetime.now(timezone.utc),
            }
        )

    alpha = config.personal_update_alpha * factor

    accumulator = _ProfileAccumulator()
    accumulator.add(event)
    # The persisted distributions are normalised (sum to 1), so blending the
    # existing distribution at weight W = (1 - alpha) / alpha against the single
    # new observation renders exactly  P' = (1 - alpha) * P + alpha * delta.
    existing_weight = (1.0 - alpha) / alpha if alpha < 1.0 else 0.0
    accumulator.merge_counts(
        {field: getattr(profile, field) or {} for field in DISTRIBUTION_FIELDS},
        weight=existing_weight,
    )

    observed_read = event.read_or_write is AccessType.READ
    observed_write = event.read_or_write is AccessType.WRITE
    prior_reads = _implied_reads(profile)
    prior_writes = _implied_writes(profile)
    blended_reads = (1.0 - alpha) * prior_reads + alpha * (1.0 if observed_read else 0.0)
    blended_writes = (1.0 - alpha) * prior_writes + alpha * (1.0 if observed_write else 0.0)
    read_write_ratio = (
        blended_reads / blended_writes
        if blended_writes > 0
        else (float("inf") if blended_reads > 0 else 0.0)
    )

    rendered = accumulator.render()
    # Only the distributions, the read/write ratio and the audit counters move
    # on a single-observation update. Aggregate scalars (avg/std events per
    # hour, privilege level, MFA expectation) are recomputed by batch rebuilds
    # (``build_profile``), never from one event.
    update_fields: dict[str, object] = {
        field: dict(rendered["distributions"][field])  # type: ignore[typeddict-item]
        for field in DISTRIBUTION_FIELDS
    }
    update_fields.update(
        {
            "event_count": profile.event_count + 1,
            "read_write_ratio": read_write_ratio,
            "baseline_version": profile.baseline_version + 1,
            "updated_at": datetime.now(timezone.utc),
        }
    )
    updated = profile.model_copy(update=update_fields)
    # Quality is re-graded conservatively: a single accepted observation can
    # keep an existing grade but must never *downgrade* it, and a cold-start
    # profile cannot jump past LIMITED without real span evidence (which only
    # ``build_profile`` can provide).
    return _regrade_preserving_floor(updated, config)


def _implied_reads(profile: IdentityProfile) -> float:
    ratio = profile.read_write_ratio or 0.0
    if math.isinf(ratio):
        return float(profile.event_count)
    if ratio <= 0:
        return 0.0
    # ratio = reads / writes and reads + writes ~= event_count.
    writes = profile.event_count / (1.0 + ratio)
    return writes * ratio


def _implied_writes(profile: IdentityProfile) -> float:
    ratio = profile.read_write_ratio or 0.0
    if math.isinf(ratio):
        return 0.0
    if ratio <= 0:
        return float(profile.event_count)
    return profile.event_count / (1.0 + ratio)


_QUALITY_RANK = {
    BaselineQuality.COLD_START: 0,
    BaselineQuality.LIMITED: 1,
    BaselineQuality.GOOD: 2,
    BaselineQuality.EXCELLENT: 3,
}


def _regrade_preserving_floor(profile: IdentityProfile, config: BaselineConfig) -> IdentityProfile:
    """Re-grade quality after a single-observation update.

    The grade can only stay or rise relative to the incoming profile, and a
    profile that was COLD_START cannot leapfrog to GOOD/EXCELLENT on the
    strength of one event.
    """
    from detection.credential_compromise.profile import assess_baseline_quality

    assessed = assess_baseline_quality(
        event_count=profile.event_count,
        span_days=(profile.observation_end - profile.observation_start).total_seconds() / 86400.0
        if profile.observation_start and profile.observation_end
        else 0.0,
        distinct_days=profile.distinct_days or 0,
        config=config,
    )
    previous = profile.baseline_quality
    if (
        _QUALITY_RANK[assessed] >= _QUALITY_RANK[BaselineQuality.GOOD]
        and _QUALITY_RANK[previous] <= _QUALITY_RANK[BaselineQuality.LIMITED]
    ):
        assessed = BaselineQuality.LIMITED
    if _QUALITY_RANK[assessed] < _QUALITY_RANK[previous]:
        assessed = previous
    return profile.model_copy(update={"baseline_quality": assessed})


# --------------------------------------------------------------------------- #
# Peer baseline
# --------------------------------------------------------------------------- #


def merge_peer_profiles(
    profiles: Sequence[IdentityProfile],
    *,
    window_days: int,
) -> Optional[IdentityProfile]:
    """Merge peer profiles into a single synthetic peer baseline.

    ``None`` when there is nothing to merge. The merged profile keeps the
    identity metadata of the first (highest-activity) peer and is explicitly
    marked cold-start-quality so downstream confidence knows its limits.
    Distributions are probability-weighted by each peer's event count.
    """
    usable = [p for p in profiles if p.event_count > 0]
    if not usable:
        return None

    total_events = sum(p.event_count for p in usable)
    fields: dict[str, object] = {}
    for field in DISTRIBUTION_FIELDS:
        blended: dict[str, float] = {}
        for peer in usable:
            weight = peer.event_count / total_events
            distribution = getattr(peer, field) or {}
            raw_total = sum(distribution.values()) or 1.0
            for value, count in distribution.items():
                blended[str(value)] = blended.get(str(value), 0.0) + weight * (count / raw_total)
        fields[field] = blended

    read_write_ratio = 0.0
    weighted_rw = [
        (p.read_write_ratio or 0.0, p.event_count / total_events)
        for p in usable
        if p.read_write_ratio and p.read_write_ratio > 0
    ]
    if weighted_rw:
        weight_sum = sum(w for _, w in weighted_rw)
        read_write_ratio = sum(v * w for v, w in weighted_rw) / weight_sum

    head = usable[0]
    return IdentityProfile(
        identity_key=head.identity_key,
        provider=head.provider,
        account_id=head.account_id,
        principal_id=head.principal_id,
        principal_name=head.principal_name,
        principal_type=head.principal_type,
        identity_kind=head.identity_kind,
        baseline_category=head.baseline_category,
        role_arn=head.role_arn,
        department=head.department,
        team=head.team,
        window_days=window_days,
        event_count=total_events,
        distinct_days=max(p.distinct_days or 0 for p in usable),
        **fields,  # type: ignore[arg-type]
        read_write_ratio=read_write_ratio,
        normal_privilege_level=head.normal_privilege_level,
        mfa_expected=any(p.mfa_expected for p in usable),
        baseline_quality=BaselineQuality.COLD_START,
        baseline_version=0,
    )


def select_effective_baseline(
    selection: BaselineSelection,
    *,
    config: BaselineConfig,
) -> tuple[Optional[IdentityProfile], str]:
    """Pick the profile whose distributions an event should be compared against.

    Returns ``(profile, reason)``. A personal baseline is used when it exists
    and is not cold-start; otherwise peers are merged (only when enough
    comparable profiles exist). Both layers are surfaced to the caller via
    ``reason`` so the two are never silently conflated.
    """
    personal = selection.profile
    if personal is not None and personal.baseline_quality is not BaselineQuality.COLD_START:
        return personal, "personal_baseline"

    peer_profile = None
    if selection.peer_count >= config.min_profiles_for_peer_baseline:
        peer_profile = merge_peer_profiles(selection.peer_profiles, window_days=selection.window_days)
    if peer_profile is not None:
        quality = personal.baseline_quality if personal is not None else BaselineQuality.COLD_START
        return peer_profile, f"peer_baseline:{quality.value}"

    return None, "no_usable_baseline"


__all__ = [
    "DISTRIBUTION_FIELDS",
    "build_profile",
    "hour_key",
    "ip_range_key",
    "merge_peer_profiles",
    "select_effective_baseline",
    "update_policy",
    "update_profile",
    "weekday_key",
]
