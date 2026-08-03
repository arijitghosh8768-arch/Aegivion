from datetime import datetime, timedelta
import enum
import bcrypt
from app.database.base import BaseModel

class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"

class User(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.email = kwargs.get("email")
        self.first_name = kwargs.get("first_name")
        self.last_name = kwargs.get("last_name")
        self.password_hash = kwargs.get("password_hash")
        self.phone = kwargs.get("phone")
        self.status = kwargs.get("status") or UserStatus.PENDING_VERIFICATION
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
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)

    def dict(self):
        res = super().dict()
        res.update({
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "password_hash": self.password_hash,
            "phone": self.phone,
            "status": self.status,
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "role_id": str(self.role_id) if self.role_id else None,
            "email_verified": self.email_verified,
            "email_verified_at": self.email_verified_at.isoformat() if isinstance(self.email_verified_at, datetime) else self.email_verified_at,
            "mfa_enabled": self.mfa_enabled,
            "mfa_secret": self.mfa_secret,
            "last_login_at": self.last_login_at.isoformat() if isinstance(self.last_login_at, datetime) else self.last_login_at,
            "last_login_ip": self.last_login_ip,
            "failed_login_attempts": self.failed_login_attempts,
            "locked_until": self.locked_until.isoformat() if isinstance(self.locked_until, datetime) else self.locked_until
        })
        return res

