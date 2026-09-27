"""Aegivion persistence layer.

Reuses a single logical findings store (``security_findings``) so the Cloud
Credential Compromise detector does not create a parallel finding system.
"""

from .database import Base, create_db_engine, create_session_factory, init_db, session_scope

__all__ = [
    "Base",
    "create_db_engine",
    "create_session_factory",
    "init_db",
    "session_scope",
]
