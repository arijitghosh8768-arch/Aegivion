import sys
import os

# Append project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal
from app.models import User, Organization, Role

def seed_database():
    db = SessionLocal()
    try:
        # Check if database is already seeded
        existing_org = db.query(Organization).filter(Organization.name == "Aegivion Demo Corp").first()
        if existing_org:
            print("Database already seeded.")
            return

        # Create organization
        org = Organization(
            name="Aegivion Demo Corp",
            slug="aegivion-demo-corp",
            industry="Technology"
        )
        db.add(org)
        db.flush() # Populate org.id

        # Create standard Roles
        admin_role = Role(name="admin", description="Full administrator access")
        analyst_role = Role(name="analyst", description="Security analyst review access")
        viewer_role = Role(name="viewer", description="Read-only access")
        
        db.add_all([admin_role, analyst_role, viewer_role])
        db.flush() # Populate role IDs

        # Create admin user
        admin = User(
            email="admin@aegivion.com",
            first_name="Admin",
            last_name="User",
            organization_id=org.id,
            role_id=admin_role.id,
            status="active",
            email_verified=True
        )
        admin.set_password("Admin123!")
        db.add(admin)
        
        db.commit()
        print("Seed data created successfully!")
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
