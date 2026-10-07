"""Configuration tests: env parsing, validation, defaults."""

from __future__ import annotations

import pytest

from algo.detection.cloud_destruction.config import (
    ENV_PREFIX,
    NORMALIZER_VERSION,
    DestructionDetectorConfig,
    load_config,
)
from algo.detection.cloud_destruction.exceptions import ConfigurationError


class TestDefaults:
    def test_defaults_load(self):
        config = load_config({})
        assert config.ingest.provider == "aws"
        assert config.ingest.strict is True
        assert config.session.idle_timeout_minutes == 30
        assert config.session.max_duration_hours == 12
        assert config.session.key_by_account is True
        assert config.storage.url == "sqlite:///:memory:"

    def test_env_prefix(self):
        assert ENV_PREFIX == "AEGIVION_DESTRUCTION_"

    def test_normalizer_version_recorded(self):
        assert NORMALIZER_VERSION  # events always carry a version


class TestEnvParsing:
    def test_overrides(self):
        config = load_config(
            {
                f"{ENV_PREFIX}SESSION_IDLE_TIMEOUT_MINUTES": "7",
                f"{ENV_PREFIX}SESSION_MAX_DURATION_HOURS": "3",
                f"{ENV_PREFIX}INGEST_STRICT": "false",
                f"{ENV_PREFIX}MAX_RECORDS_PER_BATCH": "42",
                f"{ENV_PREFIX}DEFAULT_BUSINESS_CRITICALITY": "high",
                f"{ENV_PREFIX}STORAGE_URL": "sqlite:///test.db",
            }
        )
        assert config.session.idle_timeout_minutes == 7
        assert config.session.max_duration_hours == 3
        assert config.ingest.strict is False
        assert config.ingest.max_records_per_batch == 42
        assert config.profile.default_business_criticality == "high"
        assert config.storage.url == "sqlite:///test.db"

    def test_invalid_int_rejected(self):
        with pytest.raises(ConfigurationError):
            load_config({f"{ENV_PREFIX}SESSION_IDLE_TIMEOUT_MINUTES": "soon"})

    def test_invalid_provider_rejected(self):
        with pytest.raises(ConfigurationError):
            load_config({f"{ENV_PREFIX}PROVIDER": "on-prem"})

    def test_invalid_criticality_rejected(self):
        with pytest.raises(ConfigurationError):
            load_config({f"{ENV_PREFIX}DEFAULT_BUSINESS_CRITICALITY": "mega"})


class TestPart1ConfigScope:
    def test_no_scoring_configuration_exists(self):
        """Part 1 has no score thresholds to configure — by design."""
        config = DestructionDetectorConfig()
        dumped = config.model_dump()
        assert not any("score" in key for key in dumped)
        assert not any("threshold" in key for key in dumped)
