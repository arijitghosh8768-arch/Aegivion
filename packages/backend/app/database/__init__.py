import os
import uuid
from datetime import datetime
from pymongo import MongoClient

# Load root environment variables if not already loaded
from dotenv import load_dotenv
db_dir = os.path.dirname(os.path.abspath(__file__)) # app/database
app_dir = os.path.dirname(db_dir) # app
backend_dir = os.path.dirname(app_dir) # packages/backend
packages_dir = os.path.dirname(backend_dir) # packages
load_dotenv(os.path.join(os.path.dirname(packages_dir), ".env"))

# Use MONGODB_URI or fallback to DATABASE_URL if it contains a mongodb scheme
MONGODB_URI = os.getenv("MONGODB_URI", "")
if not MONGODB_URI:
    db_url = os.getenv("DATABASE_URL", "")
    if db_url.startswith("mongodb"):
        MONGODB_URI = db_url
    else:
        MONGODB_URI = "mongodb://localhost:27017"

import certifi
client = MongoClient(MONGODB_URI, tlsAllowInvalidCertificates=True, tlsCAFile=certifi.where())
# Extract db name from URI or default to aegivion
db_name = "aegivion"
try:
    path = MONGODB_URI.split("/")[-1].split("?")[0]
    if path and "." not in path and "@" not in path:
        db_name = path
except Exception:
    pass

db = client[db_name]

# Provide a mock Base for backward compatibility
class Base:
    metadata = None

def get_collection_for_model(db_instance, model):
    name = model.__name__ if isinstance(model, type) else model.__class__.__name__
    name = name.lower()
    
    mapping = {
        "user": "users",
        "role": "roles",
        "organization": "organizations",
        "cloudaccount": "cloud_accounts",
        "cloudaccountv2": "cloud_accounts_v2",
        "cloudasset": "cloud_assets",
        "securitygroupasset": "security_groups",
        "iamuserasset": "iam_users",
        "s3bucketasset": "s3_buckets",
        "ec2instanceasset": "ec2_instances",
        "scanjob": "scan_jobs",
        "relationship": "asset_relationships",
        "assetrelationship": "asset_relationships",
        "finding": "findings"
    }
    col_name = mapping.get(name, name + "s")
    return db_instance[col_name]

def convert_filters(filters):
    res = {}
    for k, v in filters.items():
        if isinstance(v, uuid.UUID):
            res[k] = str(v)
        else:
            res[k] = v
    return res

class MockQuery:
    def __init__(self, db_instance, model_class, filters=None, order_by_field=None, desc_order=False, session=None):
        self._db = db_instance
        self._model_class = model_class
        self._filters = filters or {}
        self._order_by_field = order_by_field
        self._desc_order = desc_order
        self._session = session

    def filter(self, *expressions):
        new_filters = dict(self._filters)
        for expr in expressions:
            if isinstance(expr, tuple) and len(expr) == 2:
                field, val = expr
                new_filters[field] = val
        return MockQuery(self._db, self._model_class, new_filters, self._order_by_field, self._desc_order, self._session)

    def filter_by(self, **kwargs):
        new_filters = dict(self._filters)
        for k, v in kwargs.items():
            new_filters[k] = v
        return MockQuery(self._db, self._model_class, new_filters, self._order_by_field, self._desc_order, self._session)

    def order_by(self, expression):
        field = "started_at"
        desc = False
        if hasattr(expression, "name"):
            field = expression.name
        if hasattr(expression, "__str__") and "desc" in str(expression).lower():
            desc = True
        if hasattr(expression, "desc"):
            desc = True
        return MockQuery(self._db, self._model_class, self._filters, field, desc, self._session)

    def count(self):
        collection = get_collection_for_model(self._db, self._model_class)
        mongo_filters = convert_filters(self._filters)
        return collection.count_documents(mongo_filters)

    def all(self):
        collection = get_collection_for_model(self._db, self._model_class)
        mongo_filters = convert_filters(self._filters)
        cursor = collection.find(mongo_filters)
        if self._order_by_field:
            direction = -1 if self._desc_order else 1
            cursor = cursor.sort(self._order_by_field, direction)
        
        results = []
        for doc in cursor:
            doc_copy = dict(doc)
            if "_id" in doc_copy:
                del doc_copy["_id"]
            obj = self._model_class(**doc_copy)
            if self._session:
                self._session._queried_objects.append(obj)
            results.append(obj)
        return results

    def first(self):
        results = self.all()
        return results[0] if results else None

    def delete(self):
        collection = get_collection_for_model(self._db, self._model_class)
        mongo_filters = convert_filters(self._filters)
        collection.delete_many(mongo_filters)
        return self

class MongoSQLSession:
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
            collection = get_collection_for_model(self._db, obj)
            data = obj.dict() if hasattr(obj, "dict") else obj.__dict__
            collection.replace_one({"id": data["id"]}, data, upsert=True)
        for obj in self._queried_objects:
            collection = get_collection_for_model(self._db, obj)
            data = obj.dict() if hasattr(obj, "dict") else obj.__dict__
            collection.replace_one({"id": data["id"]}, data, upsert=True)
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
            collection.delete_one({"id": str(obj.id)})

    def execute(self, statement, *args, **kwargs):
        # Only ping if it is not a mongomock client
        if "mongomock" not in str(type(self._db.client)):
            self._db.client.admin.command('ping')
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

def get_db():
    yield MongoSQLSession(db)

def SessionLocal():
    return MongoSQLSession(db)

class MockEngine:
    url = MONGODB_URI

engine = MockEngine()


