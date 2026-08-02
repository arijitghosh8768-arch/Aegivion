import sys
import os

# Append packages/backend to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import engine
from app.database.base import Base

# Import the models module to execute its init and register all models
import app.models

def init_db():
    print("Creating SQLite database tables...")
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully!")

    # Now seed it using the seed script logic
    from scripts.seed_data import seed_database
    print("Seeding database...")
    seed_database()
    print("Database fully seeded and ready!")

if __name__ == "__main__":
    init_db()
