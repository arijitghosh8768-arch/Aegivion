"""Resource profile + protection catalog tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from detection.cloud_destruction.config import ProfileConfig
from detection.cloud_destruction.protection import (
    RecoverabilityAssessor,
    StaticProtectionCatalog,
)
from detection.cloud_destruction.exceptions import NotImplementedYetError
from detection.cloud_destruction.schemas import (
    ActionCategory,
    BusinessCriticality,
    ResourceProtectionProfile,
    ResourceType,
)

from detection.cloud_destruction.tests.helpers import advance, make_event


class TestResourceProfileBuilder:
    def test_profile_from_history(self):
        base = make_event().timestamp
        events = []
        # 6 writes and 2 deletes spread over ~2 days on one bucket
        for i in range(6):
            events.append(
                make_event(
                    event_id=f"w{i}",
                    timestamp=base + timedelta(hours=8 * i),
                    action_category=ActionCategory.CREATE,
                    resource_id="fin-prod-archive",
                    resource_arn="arn:aws:s3:::fin-prod-archive",
                    actor_id="alice.admin" if i % 2 else "ci-bot",
                )
            )
        for i in range(2):
            events.append(
                make_event(
                    event_id=f"d{i}",
                    timestamp=base + timedelta(hours=10 * i),
                    action_category=ActionCategory.DELETE,
                    resource_id="fin-prod-archive",
                    resource_arn="arn:aws:s3:::fin-prod-archive",
                )
            )
        profiles = ResourceProfileBuilderUnderTest().build_profiles(events)
        profile = profiles["fin-prod-archive"]
        assert profile.history_event_count == 8
        assert profile.observed_write_events == 6
        assert profile.observed_delete_events == 2
        assert profile.observation_start is not None
        assert profile.observation_end is not None
        assert set(profile.normal_actor_set) == {"alice.admin", "ci-bot"}
        assert profile.normal_write_rate > 0
        assert profile.normal_delete_rate > 0
        assert profile.recoverability_score is None  # Part 2

    def test_no_catalog_entry_means_none_not_guess(self):
        profiles = ResourceProfileBuilderUnderTest().build_profiles(
            [make_event(resource_id="unknown-bucket")]
        )
        profile = profiles["unknown-bucket"]
        assert profile.business_criticality is None
        assert profile.versioning_enabled is None
        assert profile.backup_enabled is None

    def test_catalog_enriches_criticality(self):
        catalog = StaticProtectionCatalog()
        catalog.add(
            ResourceProtectionProfile(
                resource_id="fin-prod-archive",
                business_criticality=BusinessCriticality.CRITICAL,
                versioning_enabled=True,
                object_lock_enabled=True,
                backup_enabled=True,
            )
        )
        events = [make_event(resource_id="fin-prod-archive")]
        profiles = ResourceProfileBuilderUnderTest(catalog).build_profiles(events)
        profile = profiles["fin-prod-archive"]
        assert profile.business_criticality is BusinessCriticality.CRITICAL
        assert profile.versioning_enabled is True
        assert profile.backup_enabled is True
        assert profile.has_protection

    def test_change_windows_recorded(self):
        profiles = ResourceProfileBuilderUnderTest().build_profiles(
            [make_event(timestamp=make_event().timestamp.replace(hour=2))]
        )
        profile = profiles["fin-prod-archive"]
        assert profile.normal_change_windows
        assert any(window.startswith("02") for window in profile.normal_change_windows)

    def test_events_without_resource_id_skipped(self):
        profiles = ResourceProfileBuilderUnderTest().build_profiles(
            [make_event(resource_id=None)]
        )
        assert profiles == {}


class ResourceProfileBuilderUnderTest:
    """Import indirection keeps the module import at test collection time."""

    def __init__(self, catalog=None, config=None):
        from detection.cloud_destruction.resource_profile import ResourceProfileBuilder

        self._builder = ResourceProfileBuilder(catalog=catalog, config=config or ProfileConfig())

    def build_profiles(self, events):
        return self._builder.build_profiles(events)


class TestRecoverabilityAssessor:
    def test_part2_scores_from_catalog_facts(self):
        """Part 2: the assessor scores remaining recoverability [0, 1]."""
        assessor = RecoverabilityAssessor()
        # no catalog facts at all -> 0.0 (upstream records 'unknown' reasons)
        assert assessor.score(ResourceProtectionProfile(resource_id="bkt")) == 0.0
        # protected backups on -> fully recoverable
        assert assessor.score(
            ResourceProtectionProfile(resource_id="bkt", backup_enabled=True)
        ) == 1.0
        # versioning without lock -> partial (0.5) recoverability
        assert assessor.score(
            ResourceProtectionProfile(resource_id="bkt", versioning_enabled=True)
        ) == 0.5
        # versioning + object lock -> fully recoverable
        assert assessor.score(
            ResourceProtectionProfile(
                resource_id="bkt", versioning_enabled=True, object_lock_enabled=True
            )
        ) == 1.0
        # every known mechanism off -> not recoverable
        assert assessor.score(
            ResourceProtectionProfile(
                resource_id="bkt",
                backup_enabled=False,
                versioning_enabled=False,
                object_lock_enabled=False,
            )
        ) == 0.0
