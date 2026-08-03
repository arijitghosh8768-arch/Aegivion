import uuid
from datetime import datetime

class MockField:
    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return (self.name, other)

    def __ne__(self, other):
        return (self.name, {"$ne": other})

    def desc(self):
        return self

class BaseModelMeta(type):
    def __getattr__(cls, key):
        if key.startswith("__") and key.endswith("__"):
            raise AttributeError
        return MockField(key)

class BaseModel(metaclass=BaseModelMeta):

    def __init__(self, **kwargs):
        self.id = kwargs.get("id") or str(uuid.uuid4())
        self.created_at = kwargs.get("created_at") or datetime.utcnow()
        self.updated_at = kwargs.get("updated_at") or datetime.utcnow()
        self.is_active = kwargs.get("is_active", True)
        self.created_by = kwargs.get("created_by")
        self.updated_by = kwargs.get("updated_by")

    def dict(self):
        return {
            "id": str(self.id),
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "updated_at": self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else self.updated_at,
            "is_active": self.is_active,
            "created_by": str(self.created_by) if self.created_by else None,
            "updated_by": str(self.updated_by) if self.updated_by else None
        }

