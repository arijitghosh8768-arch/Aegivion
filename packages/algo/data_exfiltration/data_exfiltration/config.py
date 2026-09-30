"""Configuration for Algorithm #2 (Cloud Data Exfiltration Detector).

Values here are tuning knobs only. Nothing in this module computes risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SessionConfig:
    """Tunable knobs for DataAccessSession construction.

    A session is a per-actor activity burst. Cloud data events do not carry
    an explicit session identifier, so sessions are approximated by an
    inactivity gap on the same actor.
    """

    inactivity_gap: float = 900.0
    """Seconds of inactivity that close the current session for an actor."""

    max_session_duration: float = 8.0 * 3600.0
    """Hard upper bound for one session, even if activity never stops."""

    max_actor_gap_buffer: int = 2048
    """How many idle actors to track before evicting the oldest."""


@dataclass(frozen=True)
class CorrelationConfig:
    """Tunable knobs for correlating VPC flow records into sessions."""

    enabled: bool = True
    max_time_skew: float = 120.0
    """Seconds a flow may precede the session start and still correlate."""

    destination_match_window: float = 120.0
    """Seconds around a session in which the same destination must appear."""


@dataclass(frozen=True)
class WindowConfig:
    """Aggregation windows for behavioral volume/feature computation."""

    window_sizes_seconds: tuple[float, ...] = (
        300.0,      # 5 minutes
        900.0,      # 15 minutes
        3600.0,     # 1 hour
        21600.0,    # 6 hours
        86400.0,    # 24 hours
        604800.0,   # 7 days
    )


@dataclass(frozen=True)
class BaselineEngineConfig:
    """Tuning for the multi-scope behavioral baseline engine."""

    supported_lookbacks: tuple[float, ...] = (
        7.0 * 86400.0,
        30.0 * 86400.0,
        90.0 * 86400.0,
    )
    default_lookback: float = 30.0 * 86400.0
    min_observations: int = 8
    """Minimum observations for a personal baseline to be considered warm."""
    min_peer_group_size: int = 3
    """Minimum members for a peer baseline to be used (cold start)."""
    cold_start_max_observations: int = 4
    """An entity with at most this many observations is in cold-start mode."""
    mad_z_gate: float = 3.5
    """Modified z-score gate above which an observation counts as a deviation.
    3.5 is the classical Iglewicz-Hoaglin recommendation."""


@dataclass(frozen=True)
class IntelligenceConfig:
    """Configuration for the Part 2 behavioral intelligence layer."""

    windows: WindowConfig = field(default_factory=WindowConfig)
    baseline: BaselineEngineConfig = field(default_factory=BaselineEngineConfig)


@dataclass(frozen=True)
class DetectorConfig:
    """Root configuration for the detector pipeline."""

    session: SessionConfig = field(default_factory=SessionConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    intelligence: IntelligenceConfig = field(default_factory=IntelligenceConfig)
    resource_profile_window: float = 30.0 * 86400.0
    """How far back resource profile history is summarized."""

    default_sensitivity_floor: float = 0.0
    """Score applied to resources with no known sensitivity information."""


def load_config() -> DetectorConfig:
    """Load detector configuration.

    Defaults for now; a later part can layer environment/config-file
    overrides on top of this without changing any call sites.
    """
    return DetectorConfig()
