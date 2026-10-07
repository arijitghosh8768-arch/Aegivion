"""Configuration system for the Cloud Destructive Activity Detector.

Every tunable lives here so evaluation runs can change thresholds through
environment variables instead of code. Environment variables use the
``AEGIVION_DESTRUCTION_`` prefix, e.g.::

    AEGIVION_DESTRUCTION_SESSION_IDLE_TIMEOUT_MINUTES=30
    AEGIVION_DESTRUCTION_INGEST_STRICT=false

Part 1 deliberately contains **no scoring thresholds** — no destruction
score exists yet. Configuration is limited to ingestion, session building,
profiles, and storage.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field

from algo.detection.cloud_destruction.exceptions import ConfigurationError

ENV_PREFIX = "AEGIVION_DESTRUCTION_"

#: Bumped when canonical schema or normalizer behavior changes; recorded on
#: every event's ``data_provenance.normalizer_version``.
NORMALIZER_VERSION = "1.0.0"


class IngestConfig(BaseModel):
    """Controls telemetry normalization behaviour."""

    model_config = ConfigDict(frozen=True)

    provider: str = "aws"
    strict: bool = True
    """Strict mode raises on malformed records; lenient mode quarantines them."""
    max_records_per_batch: int = Field(default=1000, ge=1)
    quarantine_on_error: bool = True
    skip_unsupported: bool = True
    """Out-of-scope-but-valid records are skipped, not counted as malformed."""
    max_parse_warnings: int = Field(default=32, ge=1)


class SessionConfig(BaseModel):
    """Controls how canonical events group into destructive sessions."""

    model_config = ConfigDict(frozen=True)

    idle_timeout_minutes: int = Field(default=30, ge=1)
    """Gap that splits one actor's stream into separate sessions."""
    max_duration_hours: int = Field(default=12, ge=1)
    """Hard cap; a longer stream is split even without an idle gap."""
    key_by_account: bool = True
    """Also split when account/region context changes mid-stream."""


class ProfileConfig(BaseModel):
    """Resource profile + protection catalog behaviour."""

    model_config = ConfigDict(frozen=True)

    default_business_criticality: str = "unclassified"
    """Applied only when the catalog has no entry; never invented per-event."""
    observation_window_days: int = Field(default=30, ge=1)
    """Descriptive window for observed history counters."""
    min_events_for_baseline: int = Field(default=50, ge=1)
    """Reserved for Part 2 baseline quality; not a score input."""


class StorageConfig(BaseModel):
    """Persistence settings."""

    model_config = ConfigDict(frozen=True)

    url: str = "sqlite:///:memory:"


class BaselineConfig(BaseModel):
    """Baseline hygiene: quality requirements and poisoning defense.

    These knobs decide which history is *learnable*, never what is risky.
    Contamination classification is deliberately conservative: sessions that
    look like bulk protection/recovery destruction stay out of the trusted
    baseline unless an approved activity profile matches them.
    """

    model_config = ConfigDict(frozen=True)

    min_sessions_for_good: int = Field(default=20, ge=1)
    min_days_for_good: float = Field(default=7.0, ge=0.5)
    min_sessions_for_limited: int = Field(default=5, ge=1)

    # poisoning-defense ladder (evidence counters on a session, not scores)
    medium_protection_change_events: int = Field(default=1, ge=0)
    """Any protection change makes a session at best limited-influence."""
    medium_version_delete_events: int = Field(default=20, ge=1)
    high_recovery_impairing_events: int = Field(default=3, ge=1)
    """Snapshot/backup/recovery-point/vault deletions at/above this: HIGH."""
    critical_recovery_impairing_events: int = Field(default=8, ge=1)
    high_destructive_ratio: float = Field(default=0.5, ge=0.0, le=1.0)
    high_destructive_events: int = Field(default=10, ge=1)


class BehavioralConfig(BaseModel):
    """Deterministic behavior-analysis constants (Part 2).

    Deviation semantics: 0.0 == at/below normal, 1.0 == at/above the
    configured factor over normal, linear in between. ``None`` == no
    baseline evidence (recorded as unavailable, never zero).
    """

    model_config = ConfigDict(frozen=True)

    max_rate_deviation_factor: float = Field(default=3.0, gt=1.0)
    ratio_deviation_factor: float = Field(default=2.0, gt=1.0)
    object_count_deviation_factor: float = Field(default=3.0, gt=1.0)
    min_session_seconds: float = Field(default=60.0, gt=0.0)
    """Floor for per-hour rate math so single-burst sessions do not divide by ~0."""

    # temporal analysis
    burst_window_minutes: int = Field(default=5, ge=1)
    burst_min_events: int = Field(default=8, ge=1)
    slow_destruction_min_hours: float = Field(default=6.0, gt=0.0)
    slow_destruction_splits: int = Field(default=3, ge=2)
    scope_expansion_factor: float = Field(default=3.0, gt=1.0)
    rapid_transition_max_gap_seconds: float = Field(default=300.0, gt=0.0)

    # absolute pacing caps used when no baseline exists (evidence-scaled only)
    version_burst_events_per_hour: float = Field(default=60.0, gt=0.0)
    snapshot_score_count_cap: int = Field(default=10, ge=1)
    recovery_score_count_cap: int = Field(default=10, ge=1)
    protection_score_count_cap: int = Field(default=3, ge=1)
    rewrite_chain_cap: int = Field(default=10, ge=1)
    delete_burst_events_per_hour: float = Field(default=120.0, gt=0.0)


class DestructionDetectorConfig(BaseModel):
    """Top-level detector configuration (Part 1 foundation + Part 2 behavior)."""

    model_config = ConfigDict(frozen=True)

    ingest: IngestConfig = Field(default_factory=IngestConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    profile: ProfileConfig = Field(default_factory=ProfileConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    baseline: BaselineConfig = Field(default_factory=BaselineConfig)
    behavioral: BehavioralConfig = Field(default_factory=BehavioralConfig)

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "DestructionDetectorConfig":
        """Build a config from environment variables (or an explicit mapping)."""
        source: Mapping[str, str] = environ if environ is not None else os.environ

        def get(name: str, default: Optional[str] = None) -> Optional[str]:
            value = source.get(f"{ENV_PREFIX}{name}")
            if value is None or value == "":
                return default
            return value

        def as_int(name: str, default: int) -> int:
            raw = get(name)
            if raw is None:
                return default
            try:
                return int(raw)
            except ValueError as exc:
                raise ConfigurationError(f"{name} must be an integer") from exc

        def as_bool(name: str, default: bool) -> bool:
            raw = get(name)
            if raw is None:
                return default
            return raw.strip().lower() in {"1", "true", "yes", "on"}

        def as_float(name: str, default: float) -> float:
            raw = get(name)
            if raw is None:
                return default
            try:
                return float(raw)
            except ValueError as exc:
                raise ConfigurationError(f"{name} must be a number") from exc

        provider = (get("PROVIDER", "aws") or "aws").lower()
        if provider not in {"aws", "azure", "gcp"}:
            raise ConfigurationError(
                "PROVIDER must be one of aws/azure/gcp", context={"got": provider}
            )
        criticality = (get("DEFAULT_BUSINESS_CRITICALITY", "unclassified") or "unclassified").lower()
        if criticality not in {"critical", "high", "medium", "low", "unclassified"}:
            raise ConfigurationError(
                "DEFAULT_BUSINESS_CRITICALITY must be critical/high/medium/low/unclassified",
                context={"got": criticality},
            )

        return cls(
            ingest=IngestConfig(
                provider=provider,
                strict=as_bool("INGEST_STRICT", True),
                max_records_per_batch=as_int("MAX_RECORDS_PER_BATCH", 1000),
                quarantine_on_error=as_bool("QUARANTINE_ON_ERROR", True),
                skip_unsupported=as_bool("SKIP_UNSUPPORTED", True),
                max_parse_warnings=as_int("MAX_PARSE_WARNINGS", 32),
            ),
            session=SessionConfig(
                idle_timeout_minutes=as_int("SESSION_IDLE_TIMEOUT_MINUTES", 30),
                max_duration_hours=as_int("SESSION_MAX_DURATION_HOURS", 12),
                key_by_account=as_bool("SESSION_KEY_BY_ACCOUNT", True),
            ),
            profile=ProfileConfig(
                default_business_criticality=criticality,
                observation_window_days=as_int("PROFILE_OBSERVATION_WINDOW_DAYS", 30),
                min_events_for_baseline=as_int("PROFILE_MIN_EVENTS_FOR_BASELINE", 50),
            ),
            storage=StorageConfig(url=get("STORAGE_URL", "sqlite:///:memory:") or "sqlite:///:memory:"),
            baseline=BaselineConfig(
                min_sessions_for_good=as_int("BASELINE_MIN_SESSIONS_GOOD", 20),
                min_days_for_good=as_float("BASELINE_MIN_DAYS_GOOD", 7.0),
                min_sessions_for_limited=as_int("BASELINE_MIN_SESSIONS_LIMITED", 5),
                high_recovery_impairing_events=as_int("POISONING_HIGH_RECOVERY_IMPAIRING", 3),
                critical_recovery_impairing_events=as_int(
                    "POISONING_CRITICAL_RECOVERY_IMPAIRING", 8
                ),
                high_destructive_ratio=as_float("POISONING_HIGH_DESTRUCTIVE_RATIO", 0.5),
                high_destructive_events=as_int("POISONING_HIGH_DESTRUCTIVE_EVENTS", 10),
            ),
            behavioral=BehavioralConfig(
                max_rate_deviation_factor=as_float("BEHAVIORAL_MAX_RATE_DEVIATION_FACTOR", 3.0),
                burst_window_minutes=as_int("BEHAVIORAL_BURST_WINDOW_MINUTES", 5),
                burst_min_events=as_int("BEHAVIORAL_BURST_MIN_EVENTS", 8),
                slow_destruction_min_hours=as_float("BEHAVIORAL_SLOW_DESTRUCTION_MIN_HOURS", 6.0),
                scope_expansion_factor=as_float("BEHAVIORAL_SCOPE_EXPANSION_FACTOR", 3.0),
                rapid_transition_max_gap_seconds=as_float(
                    "BEHAVIORAL_RAPID_TRANSITION_MAX_GAP_SECONDS", 300.0
                ),
            ),
        )


def load_config(environ: Optional[Mapping[str, str]] = None) -> DestructionDetectorConfig:
    """Load a validated :class:`DestructionDetectorConfig`."""
    if environ is not None:
        return DestructionDetectorConfig.from_env(environ)
    return _cached_config()


@lru_cache(maxsize=1)
def _cached_config() -> DestructionDetectorConfig:
    return DestructionDetectorConfig.from_env()


__all__ = [
    "BaselineConfig",
    "BehavioralConfig",
    "DestructionDetectorConfig",
    "IngestConfig",
    "NORMALIZER_VERSION",
    "ProfileConfig",
    "SessionConfig",
    "StorageConfig",
    "load_config",
]
