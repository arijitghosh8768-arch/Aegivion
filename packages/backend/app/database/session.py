import os
import logging
from typing import Generator
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

logger = logging.getLogger(__name__)

# Load local .env only. The test suite exports TEST_DATABASE_URL into the
# process before importing the app; a git-ignored .env.test must never redirect
# a running application to the isolated test database.
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
load_dotenv(os.path.join(base_dir, ".env"))

DATABASE_URL = os.getenv("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not configured. Set it in the environment (or in the "
        "git-ignored packages/backend/.env) before starting the backend."
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

def get_db() -> Generator[Session, None, None]:
    """
    Standard FastAPI dependency delivering a transactional sync SQLAlchemy Session.
    Automatically commits on normal completion and rolls back on exception.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
