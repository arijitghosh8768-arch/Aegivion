import os
import sys
import uuid
from sqlalchemy.orm import Session
from passlib.context import CryptContext

# Fix sys.path for direct execution
app_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(app_dir)
packages_dir = os.path.dirname(backend_dir)
if packages_dir not in sys.path:
    sys.path.append(packages_dir)

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(packages_dir), ".env"))

from app.database import SessionLocal
from app.models.user import User, UserStatus
from app.models.role import Role

def main():
    db: Session = SessionLocal()
    
    superadmin_email = "superadmin@aegivion.com"
    superadmin_password = "SuperSecret123!"

    # 1. Get or create Super Admin role
    superadmin_role = db.query(Role).filter(Role.name == "superadmin").first()
    if not superadmin_role:
        superadmin_role = Role(id=uuid.uuid4(), name="superadmin", description="Platform Super Admin")
        db.add(superadmin_role)
        db.commit()
        db.refresh(superadmin_role)

    # 2. Check if user exists
    user = db.query(User).filter(User.email == superadmin_email).first()
    if user:
        print(f"Super admin user {superadmin_email} already exists.")
        user.is_platform_admin = True
        user.role_id = superadmin_role.id
        db.commit()
        print("Updated existing user to Super Admin.")
        return

    # 3. Create Super Admin
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_pw = pwd_context.hash(superadmin_password)

    new_user = User(
        email=superadmin_email,
        first_name="Platform",
        last_name="SuperAdmin",
        password_hash=hashed_pw,
        status=UserStatus.ACTIVE,
        email_verified=True,
        organization_id=None,
        role_id=superadmin_role.id,
        is_platform_admin=True
    )
    
    db.add(new_user)
    db.commit()
    print(f"Success! Super Admin seeded.")
    print(f"Email: {superadmin_email}")
    print(f"Password: {superadmin_password}")
    
    db.close()

if __name__ == "__main__":
    main()
