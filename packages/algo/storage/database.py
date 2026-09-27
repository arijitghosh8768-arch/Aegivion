"""Database bootstrap.

Development and tests default to in-memory SQLite; production uses PostgreSQL
via ``AEGIVION_DATABASE_URL``. All SQLAlchemy 2.0 style, no legacy patterns.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

DEFAULT_DATABASE_URL = "sqlite+pysqlite:///:memory:"
DATABASE_URL_ENV = "AEGIVION_DATABASE_URL"


class Base(DeclarativeBase):
    """Declarative base for every Aegivion table."""


def create_db_engine(url: Optional[str] = None, **kwargs: Any) -> Engine:
    """Create an :class:`Engine`, defaulting to in-memory SQLite."""
    resolved = url or os.environ.get(DATABASE_URL_ENV) or DEFAULT_DATABASE_URL
    kwargs.setdefault("future", True)

    if resolved.startswith("sqlite"):
        kwargs.setdefault("connect_args", {"check_same_thread": False})
        if ":memory:" in resolved or resolved.endswith("sqlite://"):
            # Keep one shared connection so an in-memory DB survives across
            # sessions within a test.
            kwargs.setdefault("poolclass", StaticPool)

    return create_engine(resolved, **kwargs)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db(engine: Engine) -> None:
    """Create all tables. Import models first so metadata is populated."""
    from . import models  # noqa: F401  (registers mappings)

    Base.metadata.create_all(engine)


def drop_db(engine: Engine) -> None:
    from . import models  # noqa: F401

    Base.metadata.drop_all(engine)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional scope: commit on success, rollback on failure."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


__all__ = [
    "Base",
    "DATABASE_URL_ENV",
    "DEFAULT_DATABASE_URL",
    "create_db_engine",
    "create_session_factory",
    "drop_db",
    "init_db",
    "session_scope",
]
