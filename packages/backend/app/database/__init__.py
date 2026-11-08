import os
import uuid
from datetime import datetime
from pymongo import MongoClient
try:
    from app.database.supabase_client import supabase
except ImportError:
    supabase = None

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

# Extract db name from URI or default to aegivion
db_name = "aegivion"
try:
    path = MONGODB_URI.split("/")[-1].split("?")[0]
    if path and "." not in path and "@" not in path:
        db_name = path
except Exception:
    pass

import certifi
try:
    client = MongoClient(MONGODB_URI, tlsAllowInvalidCertificates=True, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=2000, connectTimeoutMS=2000)
    db = client[db_name]
except Exception:
    class DummyClient:
        def __getitem__(self, key):
            return {}
    client = DummyClient()
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
        "organizationmember": "organization_members",
        "authsession": "sessions",
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
        "finding": "findings",
        "vulnerability": "vulnerabilities"
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
        name = self._model_class.__name__ if isinstance(self._model_class, type) else self._model_class.__class__.__name__
        supabase_mapping = SUPABASE_MAPPING
        if supabase and name in supabase_mapping:
            table = supabase_mapping[name]
            q = supabase.table(table).select("*", count="exact")
            for k, v in self._filters.items():
                if isinstance(v, dict) and "$ne" in v:
                    q = q.neq(k, v["$ne"])
                else:
                    q = q.eq(k, str(v))
            res = q.execute()
            return res.count if hasattr(res, 'count') and res.count is not None else len(res.data)
            
        collection = get_collection_for_model(self._db, self._model_class)
        mongo_filters = convert_filters(self._filters)
        return collection.count_documents(mongo_filters)

    def all(self):
        name = self._model_class.__name__ if isinstance(self._model_class, type) else self._model_class.__class__.__name__
        supabase_mapping = SUPABASE_MAPPING
        
        if supabase and name in supabase_mapping:
            table = supabase_mapping[name]
            q = supabase.table(table).select("*")
            for k, v in self._filters.items():
                if isinstance(v, dict) and "$ne" in v:
                    q = q.neq(k, v["$ne"])
                else:
                    q = q.eq(k, str(v))
            
            try:
                res = q.execute()
                docs = res.data or []
            except Exception:
                docs = []
                
            results = []
            for doc in docs:
                obj = self._model_class(**doc)
                if self._session:
                    self._session._queried_objects.append(obj)
                results.append(obj)
            return results

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

# Re-export real SQLAlchemy SessionLocal, get_db, and engine from .session
from app.database.session import get_db, SessionLocal, engine



