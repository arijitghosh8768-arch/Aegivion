from sqlalchemy import TypeDecorator, String
from app.core.crypto import encrypt_field, decrypt_field

class EncryptedString(TypeDecorator):
    """
    SQLAlchemy TypeDecorator that transparently encrypts strings before writing
    to the database and decrypts them when reading.
    Uses Fernet (AES-128-CBC + HMAC-SHA256).
    """
    impl = String
    cache_ok = True

    def __init__(self, length=500, **kwargs):
        super().__init__(length=length, **kwargs)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return encrypt_field(str(value))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return decrypt_field(str(value))
