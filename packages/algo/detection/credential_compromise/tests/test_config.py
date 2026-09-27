"""Configuration tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from detection.credential_compromise.config import (
    DEFAULT_WEIGHTS,
    BaselineConfig,
    DetectorConfig,
    ScoringConfig,
    SessionConfig,
    load_config,
)
from detection.credential_compromise.exceptions import ConfigurationError


def test_default_weights_sum_to_one():
    assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 1e-9
    config = ScoringConfig()
    assert set(config.weights) == set(DEFAULT_WEIGHTS)


def test_default_config_is_valid():
    config = DetectorConfig()
    assert config.baseline.primary_window_days in config.baseline.windows_days
    assert config.ingest.strict is True
    assert config.session.idle_timeout_minutes == 30


def test_primary_window_must_be_in_windows():
    with pytest.raises(ConfigurationError):
        BaselineConfig(primary_window_days=14)


def test_event_thresholds_must_be_non_increasing():
    with pytest.raises(ConfigurationError):
        BaselineConfig(min_events_excellent=10, min_events_good=500)


def test_freeze_threshold_must_exceed_limited_threshold():
    with pytest.raises(ConfigurationError):
        BaselineConfig(
            baseline_freeze_risk_threshold=10.0,
            baseline_limited_influence_risk_threshold=50.0,
        )


def test_weights_cannot_omit_a_dimension():
    with pytest.raises(ConfigurationError):
        ScoringConfig(weights={"time": 1.0})


def test_weights_must_sum_to_one():
    weights = dict(DEFAULT_WEIGHTS)
    weights["time"] = 0.9
    with pytest.raises(ConfigurationError):
        ScoringConfig(weights=weights)


def test_severity_bands_must_increase():
    with pytest.raises(ConfigurationError):
        ScoringConfig(severity_low=90, severity_medium=60, severity_high=80)


def test_session_config_guards_against_zero_timeout():
    with pytest.raises(ValidationError):
        SessionConfig(idle_timeout_minutes=0)


def test_from_env_applies_overrides():
    config = DetectorConfig.from_env(
        {
            "PRIMARY_WINDOW_DAYS": "7",
            "SESSION_IDLE_TIMEOUT_MINUTES": "5",
            "INGEST_STRICT": "false",
            "SECRET_SALT": "unit-test-salt",
        }
    )
    assert config.baseline.primary_window_days == 7
    assert config.session.idle_timeout_minutes == 5
    assert config.ingest.strict is False
    assert config.secret_salt == "unit-test-salt"


def test_from_env_parses_window_list():
    config = DetectorConfig.from_env({"BASELINE_WINDOWS_DAYS": "1,7,30"})
    assert config.baseline.windows_days == (1, 7, 30)


def test_from_env_rejects_bad_window_list():
    with pytest.raises(ConfigurationError):
        DetectorConfig.from_env({"BASELINE_WINDOWS_DAYS": "seven"})


def test_from_env_parses_custom_weights():
    # Move weight between dimensions so the total stays 1.0.
    weights = dict(DEFAULT_WEIGHTS)
    weights["api"] = 0.35
    weights["device"] = 0.0

    config = DetectorConfig.from_env({"SCORING_WEIGHTS": json.dumps(weights)})
    assert config.scoring.weights["api"] == pytest.approx(0.35)
    assert config.scoring.weights["device"] == pytest.approx(0.0)


def test_from_env_rejects_bad_weights_json():
    with pytest.raises(ConfigurationError):
        DetectorConfig.from_env({"SCORING_WEIGHTS": "{not json"})


def test_load_config_with_explicit_env_skips_cache():
    config = load_config({"PROVIDER": "aws"})
    assert config.ingest.provider == "aws"
