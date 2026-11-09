# Central database exports for Aegivion backend (PostgreSQL + SQLAlchemy)
from app.database.session import get_db, SessionLocal, engine
from app.models.postgres_base import PostgresBase as Base

try:
    from app.database.supabase_client import supabase
except ImportError:
    supabase = None

__all__ = ["get_db", "SessionLocal", "engine", "supabase", "Base"]
