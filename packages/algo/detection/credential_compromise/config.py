"""Configuration system for the Cloud Credential Compromise detector.

Every tunable used by the algorithm lives here so evaluation runs can change
thresholds through environment variables instead of editing code. Nothing in
this package may hard-code a score, weight or threshold.

Environment variables use the ``AEGIVION_`` prefix, e.g.::

    AEGIVION_PRIMARY_WINDOW_DAYS=30
    AEGIVION_BASELINE_FREEZE_RISK_THRESHOLD=70
    AEGIVION_SESSION_IDLE_TIMEOUT_MINUTES=30
"""

from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime
from functools import lru_cache
from typing import Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .exceptions import ConfigurationError

ENV_PREFIX = "AEGIVION_"

DEFAULT_WEIGHTS: dict[str, float] = {
    "time": 0.15,
    "location": 0.20,
    "ip": 0.15,
    "device": 0.10,
    "api": 0.25,
    "privilege": 0.15,
}

#: Risk added by the single most severe rule signal, per severity. The total
#: signal boost is capped at the CRITICAL value so signal stacking is bounded.
DEFAULT_SIGNAL_BOOST: dict[str, float] = {
    "LOW": 0.0,
    "MEDIUM": 5.0,
    "HIGH": 12.0,
    "CRITICAL": 20.0,
}


class MaintenanceWindow(BaseModel):
    """An approved schedule during which unusual activity hours are expected.

    ``days_of_week`` uses Python weekday numbering (0=Monday .. 6=Sunday); an
    empty tuple means every day. A window may wrap midnight (``start_hour`` >
    ``end_hour``), e.g. 22 -> 6 covers an overnight batch slot.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    start_hour: int = Field(ge=0, le=23)
    end_hour: int = Field(ge=0, le=23)
    days_of_week: tuple[int, ...] = ()

    @model_validator(mode="after")
    def _check_window(self) -> "MaintenanceWindow":
        if self.start_hour == self.end_hour:
            raise ConfigurationError(
                "maintenance window start_hour and end_hour must differ",
                context={"name": self.name},
            )
        for day in self.days_of_week:
            if not 0 <= day <= 6:
                raise ConfigurationError(
                    "days_of_week must contain integers 0 (Monday) .. 6 (Sunday)",
                    context={"name": self.name, "day": day},
                )
        return self

    def covers(self, moment: datetime) -> bool:
        """Whether ``moment``'s hour-of-day and weekday fall inside the window."""
        if self.days_of_week and moment.weekday() not in self.days_of_week:
            return False
        hour = moment.hour
        if self.start_hour < self.end_hour:
            return self.start_hour <= hour < self.end_hour
        # Overnight window, e.g. 22 -> 6.
        return hour >= self.start_hour or hour < self.end_hour


class BaselineConfig(BaseModel):
    """Controls baseline windows, quality grading and learning safety."""

    model_config = ConfigDict(frozen=True)

    windows_days: tuple[int, ...] = (7, 30, 90)
    primary_window_days: int = 30

    # Sample thresholds used to grade baseline quality.
    min_events_excellent: int = Field(default=2000, ge=0)
    min_events_good: int = Field(default=500, ge=0)
    min_events_limited: int = Field(default=50, ge=0)

    min_span_days_excellent: int = Field(default=30, ge=0)
    min_span_days_good: int = Field(default=14, ge=0)
    min_span_days_limited: int = Field(default=3, ge=0)

    min_distinct_days_good: int = Field(default=7, ge=0)
    min_distinct_days_limited: int = Field(default=2, ge=0)

    # Baseline poisoning guard. Events above the freeze threshold must never be
    # folded into the baseline automatically.
    baseline_freeze_risk_threshold: float = Field(default=70.0, ge=0.0, le=100.0)
    baseline_limited_influence_risk_threshold: float = Field(default=30.0, ge=0.0, le=100.0)

    # Cold start: identities below this event count use a peer baseline.
    min_events_for_personal_baseline: int = Field(default=50, ge=0)

    # Risk-aware baseline learning (baseline poisoning protection). New
    # observations are blended into the distributions with an EMA-style weight;
    # LIMITED-influence events get a reduced weight and events at or above
    # ``baseline_freeze_risk_threshold`` are never folded in.
    personal_update_alpha: float = Field(default=0.1, ge=0.0, le=1.0)
    limited_influence_factor: float = Field(default=0.25, ge=0.0, le=1.0)

    # A peer baseline is only usable when this many comparable profiles exist.
    min_profiles_for_peer_baseline: int = Field(default=3, ge=1)

    # Corporate network ranges (CIDRs). Activity from these is trusted context,
    # not proof of familiarity: novelty is dampened, not zeroed.
    corporate_networks: tuple[str, ...] = ()

    # Approved schedules during which unusual activity hours are expected.
    maintenance_windows: tuple[MaintenanceWindow, ...] = ()

    @model_validator(mode="after")
    def _check_consistency(self) -> "BaselineConfig":
        if self.primary_window_days not in self.windows_days:
            raise ConfigurationError(
                "primary_window_days must be one of windows_days",
                context={"primary": self.primary_window_days, "windows": self.windows_days},
            )
        if not (
            self.min_events_excellent
            >= self.min_events_good
            >= self.min_events_limited
        ):
            raise ConfigurationError("event thresholds must be non-increasing")
        if not (
            self.min_span_days_excellent
            >= self.min_span_days_good
            >= self.min_span_days_limited
        ):
            raise ConfigurationError("span thresholds must be non-increasing")
        if (
            self.baseline_limited_influence_risk_threshold
            > self.baseline_freeze_risk_threshold
        ):
            raise ConfigurationError(
                "limited-influence threshold cannot exceed freeze threshold"
            )
        for cidr in self.corporate_networks:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ConfigurationError(
                    "corporate_networks entries must be valid CIDRs",
                    context={"cidr": cidr},
                ) from exc
        return self


class SessionConfig(BaseModel):
    """Controls how raw events are grouped into identity sessions."""

    model_config = ConfigDict(frozen=True)

    idle_timeout_minutes: int = Field(default=30, ge=1)
    max_duration_hours: int = Field(default=12, ge=1)
    break_on_context_change: bool = True
    context_change_fields: tuple[str, ...] = ("source_ip", "country", "user_agent")


class FeatureConfig(BaseModel):
    """Calibration for behavioral feature extraction (Part 2)."""

    model_config = ConfigDict(frozen=True)

    # Novelty smoothing: novelty = 1 - p / (p + smoothing). A key observed with
    # probability equal to the smoothing constant scores 0.5 and an unseen key
    # scores 1.0. Larger values forgive rare-but-known behaviour more.
    novelty_smoothing: float = Field(default=0.03, gt=0.0, le=1.0)

    # Minimum confidence a baseline-derived feature must carry before rules may
    # fire on it. Prevents cold-start noise storms.
    min_feature_confidence: float = Field(default=0.3, ge=0.0, le=1.0)

    # request-rate z-scores are squashed through 1 - exp(-z / squash).
    frequency_zscore_squash: float = Field(default=3.0, gt=0.0)
    burst_zscore: float = Field(default=3.0, gt=0.0)

    # v1 deterministic sequence heuristic: a privilege mutation immediately
    # after a session-start family (console sign-in / SSO / STS). Disable to
    # rely purely on learned distributions.
    enable_sequence_heuristic: bool = True

    # How strongly an identity's own privilege level dampens the intrinsic
    # privilege signal: an administrator mutating IAM is less anomalous than a
    # read-only analyst doing the same thing.
    privilege_level_dampening: dict[str, float] = Field(
        default_factory=lambda: {
            "NONE": 1.0,
            "LOW": 0.9,
            "MODERATE": 0.6,
            "ELEVATED": 0.45,
            "UNKNOWN": 0.9,
        }
    )


class RuleEngineConfig(BaseModel):
    """Rule catalogue overrides (Part 2).

    Rules can be disabled, re-severitied and re-thresholded without code
    changes; see ``detection.credential_compromise.rules``.
    """

    model_config = ConfigDict(frozen=True)

    disabled_rules: tuple[str, ...] = ()
    rule_severities: dict[str, str] = Field(default_factory=dict)
    rule_thresholds: dict[str, float] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_rules(self) -> "RuleEngineConfig":
        valid_severities = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        for rule_id, severity in self.rule_severities.items():
            if severity.upper() not in valid_severities:
                raise ConfigurationError(
                    "rule severity override must be LOW/MEDIUM/HIGH/CRITICAL",
                    context={"rule_id": rule_id, "severity": severity},
                )
        for rule_id, threshold in self.rule_thresholds.items():
            if not 0.0 <= threshold <= 1.0:
                raise ConfigurationError(
                    "rule thresholds must be within [0, 1]",
                    context={"rule_id": rule_id, "threshold": threshold},
                )
        return self


class AnomalyConfig(BaseModel):
    """Isolation Forest configuration (Part 2 ML layer)."""

    model_config = ConfigDict(frozen=True)

    trees: int = Field(default=100, ge=10, le=1000)
    subsample_size: int = Field(default=128, ge=16, le=4096)
    seed: int = Field(default=1337, ge=0)
    # Training rows below this are refused: a forest fit on a handful of rows
    # memorises rather than generalises.
    min_training_rows: int = Field(default=64, ge=1)


class FusionConfig(BaseModel):
    """Transparent, config-driven risk fusion (Part 2).

    The five scores are fused as a weighted sum whose weights must sum to 1.0;
    they are configuration, not code, and must be calibrated on evaluation
    data. They are NOT claimed to be universally optimal.
    """

    model_config = ConfigDict(frozen=True)

    # Default weights: statistics-first, rules-second, ML as corroboration.
    w_behavior: float = 0.45
    w_rule: float = 0.25
    w_anomaly: float = 0.10
    w_temporal: float = 0.15
    w_privilege: float = 0.05
    # ML anomaly output is confidence-discounted by this factor when fused so
    # an unsupervised score alone cannot dominate the ensemble.
    anomaly_confidence_discount: float = Field(default=0.5, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_weights(self) -> "FusionConfig":
        weights = {
            "w_behavior": self.w_behavior,
            "w_rule": self.w_rule,
            "w_anomaly": self.w_anomaly,
            "w_temporal": self.w_temporal,
            "w_privilege": self.w_privilege,
        }
        if any(w < 0 for w in weights.values()):
            raise ConfigurationError("fusion weights must be non-negative")
        total = sum(weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ConfigurationError("fusion weights must sum to 1.0", context={"sum": total})
        return self


class ConfidenceConfig(BaseModel):
    """Evidence-based confidence calibration (Part 2)."""

    model_config = ConfigDict(frozen=True)

    # Evidence components and their weights (must sum to 1.0). Confidence is a
    # function of evidence quality - it is never risk/100.
    w_baseline: float = 0.4
    w_corroboration: float = 0.35
    w_enrichment: float = 0.25

    @model_validator(mode="after")
    def _check(self) -> "ConfidenceConfig":
        weights = {"w_baseline": self.w_baseline, "w_corroboration": self.w_corroboration, "w_enrichment": self.w_enrichment}
        if any(w < 0 for w in weights.values()):
            raise ConfigurationError("confidence weights must be non-negative")
        if abs(sum(weights.values()) - 1.0) > 1e-6:
            raise ConfigurationError("confidence weights must sum to 1.0")
        return self


class ArdeConfig(BaseModel):
    """Adversarially Robust Detection Engine (ARDE) tuning.

    ARDE validates findings by stress-testing the evidence behind them. Every
    penalty here is a ``robustness_score`` deduction for a specific weakness;
    thresholds decide the final :class:`validation status`.
    """

    model_config = ConfigDict(frozen=True)

    # Penalties (robustness points deducted per triggered check).
    penalty_incomplete_evidence: float = 15.0
    penalty_low_feature_confidence: float = 10.0
    penalty_baseline_disagreement: float = 15.0
    penalty_rule_ml_disagreement: float = 20.0
    penalty_temporal_inconsistency: float = 10.0
    penalty_session_inconsistency: float = 10.0
    penalty_baseline_contamination: float = 15.0
    penalty_input_integrity: float = 25.0
    penalty_model_uncertainty: float = 10.0
    penalty_cross_signal_inconsistency: float = 10.0

    # Feature consistency: ML feature values must sit in [0, 1].
    feature_value_tolerance: float = Field(default=0.0, ge=0.0)

    # Evidence completeness: enrichment fields we expect on high-risk events.
    expected_evidence_fields: tuple[str, ...] = (
        "source_ip",
        "country",
        "user_agent",
    )
    min_evidence_ratio: float = Field(default=0.6, ge=0.0, le=1.0)

    # Baseline disagreement: personal vs peer deviation gap that triggers
    # a consistency check failure (peer profile must exist to compare).
    baseline_disagreement_gap: float = Field(default=0.4, ge=0.0, le=1.0)

    # Temporal: a finding whose event timestamp is wildly out of line with the
    # session timeline (future or far past relative to session start).
    max_future_skew_seconds: float = Field(default=0.0, ge=0.0)
    max_past_skew_seconds: float = Field(default=7 * 86400.0, ge=0.0)

    # Session: events-per-session bounds that indicate aggregation noise.
    max_session_duration_hours: float = Field(default=24.0, ge=0.0)

    # Input integrity: a timestamp further than this from ingest time is
    # suspicious (manipulated or clock-skewed replay).
    max_timestamp_ingest_skew_hours: float = Field(default=48.0, ge=0.0)

    # Model uncertainty: minimum acceptable normalized iForest margin
    # (mean train score minus event score) before we call the model unsure.
    min_model_margin: float = Field(default=0.1, ge=0.0)

    # Status bands on the 0-100 robustness score.
    status_rejected_below: float = Field(default=40.0, ge=0.0, le=100.0)
    status_review_below: float = Field(default=70.0, ge=0.0, le=100.0)
    status_warnings_below: float = Field(default=95.0, ge=0.0, le=100.0)

    # Rule/ML disagreement: |rule_score - anomaly_score| above this is a
    # disagreement worth flagging (both in [0, 1]).
    rule_ml_disagreement_gap: float = Field(default=0.5, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_bands(self) -> "ArdeConfig":
        if not (
            self.status_rejected_below
            < self.status_review_below
            < self.status_warnings_below
        ):
            raise ConfigurationError("ARDE status bands must be strictly increasing")
        return self


class SuppressionConfig(BaseModel):
    """False-positive suppression policy (audited, reversible, time-bound)."""

    model_config = ConfigDict(frozen=True)

    # Maximum days a suppression may stay active before it must be renewed.
    max_duration_days: int = Field(default=90, ge=1)
    # When True, suppressions never hide HIGH/CRITICAL findings entirely; they
    # downgrade them to REVIEW_REQUIRED instead of dropping them.
    never_silence_high_severity: bool = True


class IngestConfig(BaseModel):
    """Controls telemetry ingestion behaviour."""

    model_config = ConfigDict(frozen=True)

    provider: str = "aws"
    strict: bool = True
    max_records_per_batch: int = Field(default=1000, ge=1)
    quarantine_on_error: bool = True
    max_parse_warnings: int = Field(default=32, ge=1)


class ScoringConfig(BaseModel):
    """Feature weights and severity bands (consumed by the Part 2 scorer)."""

    model_config = ConfigDict(frozen=True)

    weights: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    severity_low: float = Field(default=30.0, ge=0.0, le=100.0)
    severity_medium: float = Field(default=60.0, ge=0.0, le=100.0)
    severity_high: float = Field(default=80.0, ge=0.0, le=100.0)
    severity_critical: float = Field(default=90.0, ge=0.0, le=100.0)
    signal_boost: dict[str, float] = Field(
        default_factory=lambda: dict(DEFAULT_SIGNAL_BOOST)
    )

    @model_validator(mode="after")
    def _check_weights(self) -> "ScoringConfig":
        if set(self.weights) != set(DEFAULT_WEIGHTS):
            raise ConfigurationError(
                "weights must define exactly the six behavioral dimensions",
                context={"got": sorted(self.weights)},
            )
        if any(w < 0 for w in self.weights.values()):
            raise ConfigurationError("weights must be non-negative")
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ConfigurationError("weights must sum to 1.0", context={"sum": total})
        if not (
            self.severity_low
            < self.severity_medium
            < self.severity_high
            < self.severity_critical
        ):
            raise ConfigurationError("severity bands must be strictly increasing")
        if set(self.signal_boost) != set(DEFAULT_SIGNAL_BOOST):
            raise ConfigurationError(
                "signal_boost must define exactly the four severities",
                context={"got": sorted(self.signal_boost)},
            )
        if any(b < 0 for b in self.signal_boost.values()):
            raise ConfigurationError("signal boosts must be non-negative")
        return self


class DetectorConfig(BaseModel):
    """Top level detector configuration."""

    model_config = ConfigDict(frozen=True)

    baseline: BaselineConfig = Field(default_factory=BaselineConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    ingest: IngestConfig = Field(default_factory=IngestConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    features: FeatureConfig = Field(default_factory=FeatureConfig)
    rules: RuleEngineConfig = Field(default_factory=RuleEngineConfig)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    fusion: FusionConfig = Field(default_factory=FusionConfig)
    confidence: ConfidenceConfig = Field(default_factory=ConfidenceConfig)
    arde: ArdeConfig = Field(default_factory=ArdeConfig)
    suppression: SuppressionConfig = Field(default_factory=SuppressionConfig)

    # Salt used to fingerprint access key IDs before persistence. Never store
    # key material in plaintext.
    secret_salt: str = "aegivion-default-salt"

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "DetectorConfig":
        """Build a config from environment variables (or an explicit mapping)."""
        source: Mapping[str, str]
        if environ is None:
            source = os.environ
        else:
            source = {f"{ENV_PREFIX}{k}" if not k.startswith(ENV_PREFIX) else k: v
                      for k, v in environ.items()}

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

        def as_float(name: str, default: float) -> float:
            raw = get(name)
            if raw is None:
                return default
            try:
                return float(raw)
            except ValueError as exc:
                raise ConfigurationError(f"{name} must be a number") from exc

        def as_bool(name: str, default: bool) -> bool:
            raw = get(name)
            if raw is None:
                return default
            return raw.strip().lower() in {"1", "true", "yes", "on"}

        windows_raw = get("BASELINE_WINDOWS_DAYS")
        windows: tuple[int, ...] = BaselineConfig().windows_days
        if windows_raw:
            try:
                windows = tuple(int(part) for part in windows_raw.split(",") if part.strip())
            except ValueError as exc:
                raise ConfigurationError("BASELINE_WINDOWS_DAYS must be comma separated ints") from exc

        weights = dict(DEFAULT_WEIGHTS)
        weights_raw = get("SCORING_WEIGHTS")
        if weights_raw:
            try:
                parsed = json.loads(weights_raw)
            except json.JSONDecodeError as exc:
                raise ConfigurationError("SCORING_WEIGHTS must be valid JSON") from exc
            if not isinstance(parsed, dict):  # pragma: no cover - defensive
                raise ConfigurationError("SCORING_WEIGHTS must be a JSON object")
            weights = {key: float(value) for key, value in parsed.items()}

        maintenance: list[MaintenanceWindow] = []
        maintenance_raw = get("MAINTENANCE_WINDOWS")
        if maintenance_raw:
            try:
                parsed_windows = json.loads(maintenance_raw)
                maintenance = [
                    MaintenanceWindow(**entry) for entry in parsed_windows  # type: ignore[misc]
                ]
            except (json.JSONDecodeError, TypeError, ValidationError) as exc:
                raise ConfigurationError(
                    "MAINTENANCE_WINDOWS must be valid JSON list of {name,start_hour,end_hour,days_of_week}"
                ) from exc
        corporate_raw = get("CORPORATE_NETWORKS")
        corporate: tuple[str, ...] = ()
        if corporate_raw:
            corporate = tuple(part.strip() for part in corporate_raw.split(",") if part.strip())

        baseline = BaselineConfig(
            windows_days=windows,
            primary_window_days=as_int("PRIMARY_WINDOW_DAYS", 30),
            min_events_excellent=as_int("MIN_EVENTS_EXCELLENT", 2000),
            min_events_good=as_int("MIN_EVENTS_GOOD", 500),
            min_events_limited=as_int("MIN_EVENTS_LIMITED", 50),
            min_span_days_excellent=as_int("MIN_SPAN_DAYS_EXCELLENT", 30),
            min_span_days_good=as_int("MIN_SPAN_DAYS_GOOD", 14),
            min_span_days_limited=as_int("MIN_SPAN_DAYS_LIMITED", 3),
            min_distinct_days_good=as_int("MIN_DISTINCT_DAYS_GOOD", 7),
            min_distinct_days_limited=as_int("MIN_DISTINCT_DAYS_LIMITED", 2),
            baseline_freeze_risk_threshold=as_float("BASELINE_FREEZE_RISK_THRESHOLD", 70.0),
            baseline_limited_influence_risk_threshold=as_float(
                "BASELINE_LIMITED_INFLUENCE_RISK_THRESHOLD", 30.0
            ),
            min_events_for_personal_baseline=as_int("MIN_EVENTS_FOR_PERSONAL_BASELINE", 50),
            personal_update_alpha=as_float("BASELINE_PERSONAL_UPDATE_ALPHA", 0.1),
            limited_influence_factor=as_float("BASELINE_LIMITED_INFLUENCE_FACTOR", 0.25),
            min_profiles_for_peer_baseline=as_int("MIN_PROFILES_FOR_PEER_BASELINE", 3),
            corporate_networks=corporate,
            maintenance_windows=tuple(maintenance),
        )
        session = SessionConfig(
            idle_timeout_minutes=as_int("SESSION_IDLE_TIMEOUT_MINUTES", 30),
            max_duration_hours=as_int("SESSION_MAX_DURATION_HOURS", 12),
            break_on_context_change=as_bool("SESSION_BREAK_ON_CONTEXT_CHANGE", True),
        )
        ingest = IngestConfig(
            provider=get("PROVIDER", "aws") or "aws",
            strict=as_bool("INGEST_STRICT", True),
            max_records_per_batch=as_int("MAX_RECORDS_PER_BATCH", 1000),
            quarantine_on_error=as_bool("QUARANTINE_ON_ERROR", True),
        )
        scoring = ScoringConfig(
            weights=weights,
            severity_low=as_float("SEVERITY_LOW", 30.0),
            severity_medium=as_float("SEVERITY_MEDIUM", 60.0),
            severity_high=as_float("SEVERITY_HIGH", 80.0),
            severity_critical=as_float("SEVERITY_CRITICAL", 90.0),
        )
        features = FeatureConfig(
            novelty_smoothing=as_float("FEATURE_NOVELTY_SMOOTHING", 0.03),
            min_feature_confidence=as_float("FEATURE_MIN_CONFIDENCE", 0.3),
            frequency_zscore_squash=as_float("FEATURE_FREQUENCY_ZSCORE_SQUASH", 3.0),
            burst_zscore=as_float("FEATURE_BURST_ZSCORE", 3.0),
        )
        return cls(
            baseline=baseline,
            session=session,
            ingest=ingest,
            scoring=scoring,
            features=features,
            rules=RuleEngineConfig(
                disabled_rules=tuple(
                    part.strip()
                    for part in (get("RULES_DISABLED") or "").split(",")
                    if part.strip()
                ),
            ),
            secret_salt=get("SECRET_SALT", "aegivion-default-salt") or "aegivion-default-salt",
        )


def load_config(environ: Optional[Mapping[str, str]] = None) -> DetectorConfig:
    """Load a validated :class:`DetectorConfig` from the environment."""
    if environ is not None:
        return DetectorConfig.from_env(environ)
    return _cached_config()


@lru_cache(maxsize=1)
def _cached_config() -> DetectorConfig:
    return DetectorConfig.from_env()


__all__ = [
    "AnomalyConfig",
    "ArdeConfig",
    "BaselineConfig",
    "ConfidenceConfig",
    "DEFAULT_SIGNAL_BOOST",
    "DEFAULT_WEIGHTS",
    "DetectorConfig",
    "FeatureConfig",
    "FusionConfig",
    "IngestConfig",
    "MaintenanceWindow",
    "RuleEngineConfig",
    "ScoringConfig",
    "SessionConfig",
    "SuppressionConfig",
    "load_config",
]
