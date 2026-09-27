"""Shared fixtures for the Cloud Credential Compromise foundation tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import pytest

from detection.credential_compromise.schemas import (
    BaselineCategory,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    PrincipalType,
)
from storage.database import (
    create_db_engine,
    create_session_factory,
    init_db,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "cloudtrail"


def load_cloudtrail_fixture(name: str) -> dict[str, Any]:
    """Load a JSON CloudTrail fixture by file name."""
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture
def cloudtrail() -> Callable[[str], dict[str, Any]]:
    return load_cloudtrail_fixture


@pytest.fixture
def make_event() -> Callable[..., IdentityActivityEvent]:
    """Factory for minimal valid canonical events."""

    def _make(**overrides: Any) -> IdentityActivityEvent:
        payload: dict[str, Any] = {
            "event_id": "evt-0001",
            "timestamp": datetime(2026, 9, 20, 9, 45, 12, tzinfo=timezone.utc),
            "principal_id": "arn:aws:iam::123456789012:user/aniruddha",
            "principal_name": "aniruddha",
            "principal_type": PrincipalType.IAM_USER,
            "identity_kind": IdentityKind.HUMAN,
            "baseline_category": BaselineCategory.HUMAN_USER,
            "identity_key": "aws:123456789012:human_user:arn:aws:iam::123456789012:user/aniruddha",
            "event_source": "iam.amazonaws.com",
            "event_name": "GetUser",
            "event_category": EventCategory.MANAGEMENT,
            "service_name": "iam",
            "api_family": "IAM_READ",
            "account_id": "123456789012",
            "region": "ap-south-1",
        }
        payload.update(overrides)
        return IdentityActivityEvent(**payload)

    return _make


@pytest.fixture
def db_session():
    """A live ORM session against an isolated in-memory SQLite database."""
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    init_db(engine)
    factory = create_session_factory(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
