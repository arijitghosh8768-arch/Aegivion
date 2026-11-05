from datetime import datetime, timezone
import uuid
from typing import Any, Dict
from sqlalchemy import Column, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from app.models.postgres_base import PostgresBase

# Unified Declarative Base across all modules
Base = PostgresBase

class MockField:
    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return (self.name, other)

    def __ne__(self, other):
        return (self.name, {"$ne": other})

    def desc(self):
        return self

class LegacyBaseModelMeta(type):
    def __getattr__(cls, key):
        if key.startswith("__") and key.endswith("__"):
            raise AttributeError
        return MockField(key)

class LegacyBaseModel(metaclass=LegacyBaseModelMeta):
    """Base class for unmigrated domains (Batch 2-5)."""
    def __init__(self, **kwargs):
        self.id = kwargs.get("id") or str(uuid.uuid4())
        self.created_at = kwargs.get("created_at") or datetime.now(timezone.utc)
        self.updated_at = kwargs.get("updated_at") or datetime.now(timezone.utc)
        self.is_active = kwargs.get("is_active", True)
        self.created_by = kwargs.get("created_by")
        self.updated_by = kwargs.get("updated_by")

    def dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            "updated_at": self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else self.updated_at,
            "is_active": self.is_active,
            "created_by": str(self.created_by) if getattr(self, "created_by", None) else None,
            "updated_by": str(self.updated_by) if getattr(self, "updated_by", None) else None
        }

class BaseModel(Base):
    """Declarative Base class for migrated SQLAlchemy models (Batch 1)."""
    __abstract__ = True

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(UUID(as_uuid=True), nullable=True)
    updated_by = Column(UUID(as_uuid=True), nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "id" in kwargs and kwargs["id"] is not None:
            val = kwargs["id"]
            if isinstance(val, str):
                try:
                    self.id = uuid.UUID(val)
                except ValueError:
                    self.id = val
            else:
                self.id = val
        elif not getattr(self, "id", None):
            self.id = uuid.uuid4()

        if "created_at" in kwargs and kwargs["created_at"] is not None:
            self.created_at = kwargs["created_at"]
        elif not getattr(self, "created_at", None):
            self.created_at = datetime.now(timezone.utc)

        if "updated_at" in kwargs and kwargs["updated_at"] is not None:
            self.updated_at = kwargs["updated_at"]
        elif not getattr(self, "updated_at", None):
            self.updated_at = datetime.now(timezone.utc)

        if "is_active" in kwargs:
            self.is_active = kwargs["is_active"]
        if "created_by" in kwargs:
            self.created_by = kwargs["created_by"]
        if "updated_by" in kwargs:
            self.updated_by = kwargs["updated_by"]

    def dict(self) -> Dict[str, Any]:
        result = {}
        for c in self.__table__.columns:
            val = getattr(self, c.name, None)
            if isinstance(val, uuid.UUID):
                result[c.name] = str(val)
            elif isinstance(val, datetime):
                result[c.name] = val.isoformat()
            else:
                result[c.name] = val
        return result
