import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from app.core.config import settings

def _get_fernet() -> Fernet:
    """Retrieve or derive the Fernet cipher instance."""
    key = settings.ENCRYPTION_KEY
    if not key:
        # Deterministic fallback for dev/test environments derived from SECRET_KEY
        derived = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        key = base64.urlsafe_b64encode(derived).decode()
    elif isinstance(key, str):
        # If user passed a plain 32-byte string instead of urlsafe base64, normalize it
        try:
            Fernet(key.encode() if isinstance(key, str) else key)
        except Exception:
            derived = hashlib.sha256(key.encode()).digest()
            key = base64.urlsafe_b64encode(derived).decode()

    return Fernet(key.encode() if isinstance(key, str) else key)

def encrypt_field(plaintext: Optional[str]) -> Optional[str]:
    """Encrypt a plaintext string using Fernet (AES-128-CBC + HMAC-SHA256)."""
    if plaintext is None:
        return None
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    cipher = _get_fernet()
    return cipher.encrypt(plaintext.encode("utf-8")).decode("utf-8")

def decrypt_field(ciphertext: Optional[str]) -> Optional[str]:
    """
    Decrypt a Fernet token.
    Gracefully returns original value if decryption fails (e.g., existing legacy plaintext).
    """
    if ciphertext is None:
        return None
    if not isinstance(ciphertext, str):
        ciphertext = str(ciphertext)

    try:
        cipher = _get_fernet()
        return cipher.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception):
        # Graceful fallback: value was already plaintext before migration
        return ciphertext
