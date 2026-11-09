import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.abspath(os.path.join(current_dir, ".."))
packages_dir = os.path.abspath(os.path.join(backend_dir, ".."))

sys.path.insert(0, backend_dir)
sys.path.insert(0, packages_dir)
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from app.main import app
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
