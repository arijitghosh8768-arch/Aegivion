import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.abspath(os.path.join(current_dir, ".."))
packages_dir = os.path.abspath(os.path.join(backend_dir, ".."))

sys.path.insert(0, backend_dir)
sys.path.insert(0, packages_dir)
import pytest
from fastapi.testclient import TestClient
import mongomock
from app.main import app
from app.database import get_db
from app.database import get_collection_for_model, MockQuery

class MockSessionForTests:
    """Isolated test session mock for unit tests that override get_db."""
    def __init__(self, db_instance):
        self._db = db_instance
        self._new_objects = []
        self._queried_objects = []

    def query(self, model_class):
        return MockQuery(self._db, model_class, session=self)

    def add(self, obj):
        self._new_objects.append(obj)

    def commit(self):
        for obj in self._new_objects:
            data = obj.dict() if hasattr(obj, "dict") else obj.__dict__
            collection = get_collection_for_model(self._db, obj)
            collection.replace_one({"id": data.get("id")}, data, upsert=True)
            
        for obj in self._queried_objects:
            data = obj.dict() if hasattr(obj, "dict") else obj.__dict__
            collection = get_collection_for_model(self._db, obj)
            collection.replace_one({"id": data.get("id")}, data, upsert=True)
            
        self._new_objects = []
        self._queried_objects = []

    def refresh(self, obj):
        pass

    def rollback(self):
        self._new_objects = []
        self._queried_objects = []

    def delete(self, obj=None):
        if obj:
            collection = get_collection_for_model(self._db, obj)
            collection.delete_one({"id": str(getattr(obj, "id", ""))})

    def execute(self, statement, *args, **kwargs):
        class MockResult:
            def fetchall(self):
                return []
        return MockResult()

    def add_all(self, objects):
        for obj in objects:
            self.add(obj)

    def flush(self):
        self.commit()

    def close(self):
        pass

@pytest.fixture(scope="session")
def test_db():
    client = mongomock.MongoClient()
    return client["aegivion_test"]

@pytest.fixture
def test_session(test_db):
    # Clear collections before each test for test isolation
    for col in test_db.list_collection_names():
        test_db[col].delete_many({})
    
    session = MockSessionForTests(test_db)
    yield session
    session.rollback()

@pytest.fixture
def client(test_session):
    def override_get_db():
        yield test_session
    
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()
