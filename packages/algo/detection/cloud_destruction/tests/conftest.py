"""Shared pytest fixtures for the Cloud Destructive Activity Detector tests."""

from __future__ import annotations

import pytest

from algo.detection.cloud_destruction.provenance import AvailabilityTracker
from algo.detection.cloud_destruction.tests.helpers import BASE_TIME, make_event


@pytest.fixture()
def tracker() -> AvailabilityTracker:
    return AvailabilityTracker()


@pytest.fixture()
def base_time():
    return BASE_TIME


@pytest.fixture()
def sample_event():
    return make_event()
