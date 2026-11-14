import os
import logging
from typing import Generator, Optional
from contextvars import ContextVar
from dotenv import dotenv_values, load_dotenv
from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import sessionmaker, Session

# Tenant context variable for Row-Level Security
current_tenant_org_id: ContextVar[Optional[str]] = ContextVar("current_tenant_org_id", default=None)

def set_session_tenant(db: Session, org_id: Optional[str]) -> None:
    """Set the PostgreSQL session variable app.current_org_id and switch to tenant role for Row-Level Security."""
    if org_id:
        db.execute(text("SET ROLE authenticated;"))
        db.execute(text("SET LOCAL app.current_org_id = :org_id"), {"org_id": str(org_id)})
    else:
        db.execute(text("RESET ROLE;"))
        db.execute(text("SET LOCAL app.current_org_id = ''"))

logger = logging.getLogger(__name__)

# Load local .env and .env.test if present
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
load_dotenv(os.path.join(base_dir, ".env"))

env_test_file = os.path.join(base_dir, ".env.test")
test_env_vals = dotenv_values(env_test_file) if os.path.exists(env_test_file) else {}

DATABASE_URL = (
    os.getenv("TEST_DATABASE_URL")
    or test_env_vals.get("TEST_DATABASE_URL")
    or os.getenv("DATABASE_URL", "postgresql://aegivion:aegivion123@localhost:5432/aegivion")
)

# Fail-Fast in production if DATABASE_URL is pointing to localhost or is missing
environment = os.getenv("ENVIRONMENT", "development").lower()
is_localhost = any(h in DATABASE_URL for h in ("localhost", "127.0.0.1", "::1"))

if environment in ("production", "prod") and is_localhost:
    err_msg = (
        "CRITICAL DATABASE CONFIGURATION ERROR: ENVIRONMENT is set to 'production', "
        "but DATABASE_URL points to localhost or is unconfigured. "
        "Please configure a valid managed PostgreSQL connection string (e.g. Supabase) on Render."
    )
    logger.critical(err_msg)
    raise RuntimeError(err_msg)

# Ensure postgresql+psycopg2:// scheme is used for psycopg2 driver
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# Enforce sslmode=require for remote cloud databases (e.g. Supabase, Render Postgres)
connect_args = {}
if not is_localhost and "sslmode" not in DATABASE_URL:
    if "?" in DATABASE_URL:
        DATABASE_URL += "&sslmode=require"
    else:
        DATABASE_URL += "?sslmode=require"
    connect_args["sslmode"] = "require"

# Create synchronous engine with connection pooling and timeout resilience
engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=300,
    pool_pre_ping=True,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

@event.listens_for(Session, "after_begin")
def receive_after_begin(session, transaction, connection):
    """Automatically inject app.current_org_id into the PostgreSQL transaction if set in context."""
    org_id = current_tenant_org_id.get()
    if org_id:
        connection.execute(text("SET ROLE authenticated;"))
        connection.execute(text("SET LOCAL app.current_org_id = :org_id"), {"org_id": str(org_id)})
    else:
        connection.execute(text("RESET ROLE;"))

def get_db() -> Generator[Session, None, None]:
    """
    Standard FastAPI dependency delivering a transactional sync SQLAlchemy Session.
    Automatically commits on normal completion and rolls back on exception.
    """
    db = SessionLocal()
    org_id = current_tenant_org_id.get()
    if org_id:
        try:
            set_session_tenant(db, org_id)
        except Exception:
            pass
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
