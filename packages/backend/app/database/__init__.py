import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://aegivion_user:aegivion_pass@localhost:5432/aegivion_db"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
from app.database.base import Base

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
