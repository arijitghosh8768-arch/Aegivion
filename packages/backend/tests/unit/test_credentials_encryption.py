import os
import uuid
import pytest
from sqlalchemy import text
from app.core.crypto import encrypt_field, decrypt_field
from app.models.cloud import CloudAccount
from app.models.cloud_account import CloudAccountV2
from app.models.organization import Organization
from app.database.session import SessionLocal

def test_crypto_roundtrip():
    """Verify encrypt_field and decrypt_field work accurately."""
    plaintext = "super-secret-aws-key-12345!@#"
    ciphertext = encrypt_field(plaintext)
    
    assert ciphertext != plaintext
    assert isinstance(ciphertext, str)
    assert len(ciphertext) > len(plaintext)
    
    decrypted = decrypt_field(ciphertext)
    assert decrypted == plaintext

def test_crypto_plaintext_fallback():
    """Verify legacy plaintext gracefully passes through decrypt_field without error."""
    legacy_value = "legacy-unencrypted-secret"
    decrypted = decrypt_field(legacy_value)
    assert decrypted == legacy_value

def test_crypto_none_handling():
    """Verify None input returns None."""
    assert encrypt_field(None) is None
    assert decrypt_field(None) is None

def test_cloud_account_encryption_at_rest():
    """
    Verify that when saving a CloudAccount:
    1. Python attribute access yields decrypted plaintext.
    2. Direct raw SQL execution on the database yields encrypted ciphertext.
    """
    db = SessionLocal()
    org_id = uuid.uuid4()
    org_slug = f"test-org-{uuid.uuid4().hex[:8]}"
    org = Organization(id=org_id, name="Encryption Test Org", slug=org_slug)
    db.add(org)
    db.commit()

    raw_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    raw_ext_id = "test-external-id-987654321"

    account = CloudAccount(
        name="Encrypted Test Account",
        provider="AWS",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key=raw_secret,
        external_id=raw_ext_id,
        role_arn="arn:aws:iam::123456789012:role/TestRole",
        organization_id=org_id
    )
    db.add(account)
    db.commit()
    account_id = account.id

    try:
        # 1. Fetch via SQLAlchemy ORM - attributes should be transparently decrypted
        db.expire_all()
        fetched = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
        assert fetched is not None
        assert fetched.aws_secret_access_key == raw_secret
        assert fetched.external_id == raw_ext_id
        # role_arn and access key are plain strings
        assert fetched.role_arn == "arn:aws:iam::123456789012:role/TestRole"
        assert fetched.aws_access_key_id == "AKIAIOSFODNN7EXAMPLE"

        # 2. Raw SQL query bypassing ORM TypeDecorator - must be encrypted at rest in DB
        result = db.execute(
            text("SELECT aws_secret_access_key, external_id, role_arn FROM cloud_accounts WHERE id = :id"),
            {"id": str(account_id)}
        ).fetchone()

        assert result is not None
        db_secret, db_ext_id, db_role = result[0], result[1], result[2]

        # Plaintext secrets MUST NOT appear directly in the database
        assert db_secret != raw_secret
        assert db_ext_id != raw_ext_id
        assert db_role == "arn:aws:iam::123456789012:role/TestRole"

        # Decrypting raw database strings recovers the original secrets
        assert decrypt_field(db_secret) == raw_secret
        assert decrypt_field(db_ext_id) == raw_ext_id

    finally:
        db.delete(account)
        db.delete(org)
        db.commit()
        db.close()

def test_cloud_account_v2_encryption_at_rest():
    """
    Verify CloudAccountV2 external_id is encrypted at rest.
    """
    db = SessionLocal()
    org_id = uuid.uuid4()
    org_slug = f"test-org-v2-{uuid.uuid4().hex[:8]}"
    org = Organization(id=org_id, name="Encryption Test Org V2", slug=org_slug)
    db.add(org)
    db.commit()

    raw_ext_id = "v2-sts-external-id-456"
    account = CloudAccountV2(
        organization_id=org_id,
        account_id="123456789012",
        account_name="V2 Test Account",
        role_arn="arn:aws:iam::123456789012:role/V2Role",
        external_id=raw_ext_id
    )
    db.add(account)
    db.commit()
    account_id = account.id

    try:
        db.expire_all()
        fetched = db.query(CloudAccountV2).filter(CloudAccountV2.id == account_id).first()
        assert fetched is not None
        assert fetched.external_id == raw_ext_id
        assert fetched.role_arn == "arn:aws:iam::123456789012:role/V2Role"

        result = db.execute(
            text("SELECT external_id, role_arn FROM cloud_accounts_v2 WHERE id = :id"),
            {"id": str(account_id)}
        ).fetchone()

        assert result is not None
        db_ext_id, db_role = result[0], result[1]

        assert db_ext_id != raw_ext_id
        assert db_role == "arn:aws:iam::123456789012:role/V2Role"
        assert decrypt_field(db_ext_id) == raw_ext_id

    finally:
        db.delete(account)
        db.delete(org)
        db.commit()
        db.close()
