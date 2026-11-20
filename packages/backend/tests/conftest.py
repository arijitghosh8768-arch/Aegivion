"""Shared pytest fixtures for the backend test suite.

The isolated PostgreSQL RAG database configuration lives in
``packages/backend/.env.test`` (git-ignored). It is loaded here *before* the
application is imported so no module can bind the application database.
"""

import os
import sys

# conftest.py is at: packages/backend/tests/conftest.py
conftest_dir = os.path.dirname(os.path.abspath(__file__))  # packages/backend/tests
backend_dir = os.path.abspath(os.path.join(conftest_dir, ".."))  # packages/backend
packages_dir = os.path.abspath(os.path.join(backend_dir, ".."))  # packages


def _database_basename(url: str) -> str:
    return (url or "").rsplit("/", 1)[-1].split("?", 1)[0]


# Set TEST_DATABASE_URL before importing app. The test configuration belongs to
# the backend package; reading a repository-root file previously pointed the
# suite at the application database instead of the isolated test database.
test_db_url = os.getenv("TEST_DATABASE_URL")
if not test_db_url:
    env_test_file = os.path.join(backend_dir, ".env.test")
    if os.path.exists(env_test_file):
        from dotenv import dotenv_values

        test_db_url = dotenv_values(env_test_file).get("TEST_DATABASE_URL")

if test_db_url:
    db_name = _database_basename(test_db_url)
    if not db_name.endswith("_test"):
        raise RuntimeError(
            "Refusing to run tests: TEST_DATABASE_URL must point at a dedicated "
            f"test database (got database {db_name!r})."
        )
    os.environ["TEST_DATABASE_URL"] = test_db_url
    # Background workers must never run inside the test process: they would
    # scan fixture accounts concurrently with the test's own transaction.
    os.environ["ENVIRONMENT"] = "test"
    # Never print the URL itself: it carries the database password.
    print(
        f"DEBUG: TEST_DATABASE_URL configured for database {db_name!r}",
        file=sys.stderr,
    )
else:
    print("DEBUG: TEST_DATABASE_URL is not configured", file=sys.stderr)

# Insert paths
sys.path.insert(0, backend_dir)
sys.path.insert(0, packages_dir)

import pytest
from unittest.mock import MagicMock

from app.main import app
from fastapi.testclient import TestClient

from app.database import get_db


@pytest.fixture
def mock_db():
    db = MagicMock()
    return db


@pytest.fixture
def client(mock_db):
    def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()
