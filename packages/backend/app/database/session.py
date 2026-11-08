import os
import logging
from typing import Generator
from dotenv import dotenv_values, load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

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

# Ensure postgresql+psycopg2:// scheme is used for psycopg2 driver
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# Create synchronous engine with connection pooling
engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=1800,
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
