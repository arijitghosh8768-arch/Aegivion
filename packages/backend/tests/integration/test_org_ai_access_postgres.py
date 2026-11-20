"""PostgreSQL integration tests for the organization AI-access gate.

Runs against ``TEST_DATABASE_URL`` (an isolated database) and exercises the real
``organizations`` table. Every row created here is removed afterwards.

Covers: allowed access, denied access, missing settings, missing organization,
tenant isolation and an unresolvable tenant identifier, plus the two API
endpoints that previously crashed on the legacy ``OrgSettings`` model.
"""

import json
import os
import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.organization import Organization
from app.services.org_ai_access import is_ai_enabled_for_organization

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not (TEST_DATABASE_URL and TEST_DATABASE_URL.startswith("postgresql")),
    reason="TEST_DATABASE_URL is not configured for PostgreSQL",
)


def _pg_url():
    """Force psycopg2; the bare scheme resolves to psycopg v3 which is not installed."""
    if TEST_DATABASE_URL.startswith("postgresql+psycopg2://"):
        return TEST_DATABASE_URL
    return TEST_DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)


@pytest.fixture
def db():
    engine = create_engine(_pg_url())
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        engine.dispose()
        pytest.skip(f"PostgreSQL unreachable: {exc}")

    session = sessionmaker(bind=engine)()
    created = []

    def _make_org(settings=None):
        org = Organization(
            id=uuid.uuid4(),
            name=f"AI Access Test {uuid.uuid4().hex[:8]}",
            slug=f"ai-access-{uuid.uuid4().hex[:12]}",
            settings=settings if settings is not None else {},
        )
        session.add(org)
        session.commit()
        created.append(org.id)
        return org

    try:
        yield session, _make_org
    finally:
        try:
            session.rollback()
            for org_id in created:
                session.query(Organization).filter(Organization.id == org_id).delete(
                    synchronize_session=False
                )
            session.commit()
        except Exception:  # noqa: BLE001 - best-effort cleanup
            session.rollback()
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# gate semantics
# ---------------------------------------------------------------------------
def test_ai_enabled_when_setting_explicitly_true(db):
    session, make_org = db
    org = make_org({"ai_features_enabled": True})
    assert is_ai_enabled_for_organization(session, org.id) is True


def test_ai_disabled_when_setting_explicitly_false(db):
    session, make_org = db
    org = make_org({"ai_features_enabled": False})
    assert is_ai_enabled_for_organization(session, org.id) is False


def test_ai_enabled_when_settings_are_missing(db):
    session, make_org = db
    org = make_org({})
    assert is_ai_enabled_for_organization(session, org.id) is True


def test_ai_enabled_for_unknown_organization_preserves_legacy_behaviour(db):
    session, _ = db
    assert is_ai_enabled_for_organization(session, uuid.uuid4()) is True


def test_ai_denied_for_unresolvable_tenant_identifier(db):
    """A caller that cannot be matched to an organization must be denied."""
    session, _ = db
    assert is_ai_enabled_for_organization(session, "not-a-uuid") is False
    assert is_ai_enabled_for_organization(session, None) is False


def test_tenant_isolation_between_organizations(db):
    session, make_org = db
    disabled = make_org({"ai_features_enabled": False})
    enabled = make_org({"ai_features_enabled": True})

    assert is_ai_enabled_for_organization(session, disabled.id) is False
    assert is_ai_enabled_for_organization(session, enabled.id) is True
    # Re-check the first org: the second lookup must not leak state.
    assert is_ai_enabled_for_organization(session, disabled.id) is False


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
def _llm_json():
    return json.dumps(
        {
            "response": "Grounded answer.",
            "observed": [],
            "inferred": [],
            "unknown": [],
            "declined": False,
        }
    )


@pytest.fixture
def api(db):
    from fastapi.testclient import TestClient

    from app.api.deps import get_current_user
    from app.database import get_db
    from app.main import app

    session, make_org = db

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app), session, make_org, app, get_current_user
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


@patch("app.api.v1.chat.get_llm_provider")
def test_chat_returns_403_when_ai_disabled(mock_provider, api):
    client, session, make_org, app, get_current_user = api
    org = make_org({"ai_features_enabled": False})
    app.dependency_overrides[get_current_user] = lambda: {
        "id": str(uuid.uuid4()),
        "organization_id": str(org.id),
    }

    response = client.post("/api/v1/ai/chat", json={"message": "hello"})

    assert response.status_code == 403
    assert "AI features are not enabled" in response.json()["detail"]
    mock_provider.return_value.generate.assert_not_called()


@patch("app.api.v1.chat.get_llm_provider")
def test_chat_succeeds_when_ai_enabled(mock_provider, api):
    client, session, make_org, app, get_current_user = api
    org = make_org({"ai_features_enabled": True})
    app.dependency_overrides[get_current_user] = lambda: {
        "id": str(uuid.uuid4()),
        "organization_id": str(org.id),
    }
    mock_provider.return_value.generate.return_value = _llm_json()

    response = client.post("/api/v1/ai/chat", json={"message": "hello"})

    assert response.status_code == 200
    assert response.json()["response"] == "Grounded answer."


@patch("app.api.v1.chat.get_llm_provider")
def test_chat_does_not_crash_for_organization_with_no_settings_row(mock_provider, api):
    """Previously this raised ArgumentError from the legacy OrgSettings model."""
    client, session, make_org, app, get_current_user = api
    org = make_org({})
    app.dependency_overrides[get_current_user] = lambda: {
        "id": str(uuid.uuid4()),
        "organization_id": str(org.id),
    }
    mock_provider.return_value.generate.return_value = _llm_json()

    response = client.post("/api/v1/ai/chat", json={"message": "hello"})

    assert response.status_code == 200


def test_explain_handler_denies_when_ai_disabled(db):
    """The explain handler must deny AI access when the organization disabled it.

    ``app.api.v1.explain`` is not included on the application router, so the
    handler is exercised directly rather than over HTTP. The gate therefore runs
    before any finding lookup (which still relies on a legacy model).
    """
    import asyncio

    from fastapi import HTTPException
    from starlette.requests import Request

    from app.api.v1.explain import ExplainRequest, explain_finding

    session, make_org = db
    org = make_org({"ai_features_enabled": False})
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 1234),
        "scheme": "http",
    }

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            explain_finding(
                Request(scope),
                "00000000-0000-0000-0000-000000000000",
                ExplainRequest(finding_id="00000000-0000-0000-0000-000000000000"),
                db=session,
                current_user={
                    "id": str(uuid.uuid4()),
                    "organization_id": str(org.id),
                },
            )
        )

    assert exc_info.value.status_code == 403
    assert "AI features are not enabled" in exc_info.value.detail
