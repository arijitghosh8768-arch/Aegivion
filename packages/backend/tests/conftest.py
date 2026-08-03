import pytest
from fastapi.testclient import TestClient
import mongomock
from app.main import app
from app.database import get_db, MongoSQLSession

@pytest.fixture(scope="session")
def test_db():
    client = mongomock.MongoClient()
    return client["aegivion_test"]

@pytest.fixture
def test_session(test_db):
    # Clear collections before each test for test isolation
    for col in test_db.list_collection_names():
        test_db[col].delete_many({})
    
    session = MongoSQLSession(test_db)
    yield session
    session.rollback()

@pytest.fixture
def client(test_session):
    def override_get_db():
        yield test_session
    
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()
