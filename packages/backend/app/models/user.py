from datetime import datetime, timezone, timedelta
import enum
import bcrypt
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Index
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel

class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"

class User(BaseModel):
    __tablename__ = "users"

    email = Column(String(255), unique=True, nullable=False, index=True)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    password_hash = Column(String(255), nullable=False)
    phone = Column(String(20), nullable=True)
    status = Column(String(50), default="pending_verification")
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False)

    # Security features
    email_verified = Column(Boolean, default=False)
    email_verified_at = Column(DateTime(timezone=True), nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="users", foreign_keys=[organization_id])
    role = relationship("Role", back_populates="users")
    memberships = relationship("OrganizationMember", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("AuthSession", back_populates="user", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.email = kwargs.get("email")
        self.first_name = kwargs.get("first_name")
        self.last_name = kwargs.get("last_name")
        self.password_hash = kwargs.get("password_hash")
        self.phone = kwargs.get("phone")
        self.status = kwargs.get("status") or UserStatus.PENDING_VERIFICATION.value
        self.organization_id = kwargs.get("organization_id")
        self.role_id = kwargs.get("role_id")
        self.email_verified = kwargs.get("email_verified", False)
        self.email_verified_at = kwargs.get("email_verified_at")
        self.mfa_enabled = kwargs.get("mfa_enabled", False)
        self.mfa_secret = kwargs.get("mfa_secret")
        self.last_login_at = kwargs.get("last_login_at")
        self.last_login_ip = kwargs.get("last_login_ip")
        self.failed_login_attempts = kwargs.get("failed_login_attempts") or 0
        self.locked_until = kwargs.get("locked_until")

    def verify_password(self, password: str) -> bool:
        if not self.password_hash or self.password_hash == "GOOGLE_OAUTH_NO_PASSWORD":
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except Exception:
            return False

    def set_password(self, password: str):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def increment_failed_attempts(self):
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
