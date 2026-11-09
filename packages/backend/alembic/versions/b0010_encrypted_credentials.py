"""expand credential columns for ciphertext
Revision ID: b0010_encrypted_credentials
Revises: b0009_batch9_remediation
Create Date: 2026-11-09 23:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'b0010_encrypted_credentials'
down_revision: Union[str, None] = 'b0009_batch9_remediation'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Expand cloud_accounts columns to length 500 to store Fernet base64 ciphertext
    op.alter_column('cloud_accounts', 'aws_secret_access_key',
               existing_type=sa.String(length=100),
               type_=sa.String(length=500),
               existing_nullable=True)
    op.alter_column('cloud_accounts', 'external_id',
               existing_type=sa.String(length=100),
               type_=sa.String(length=500),
               existing_nullable=True)

    # Expand cloud_accounts_v2 external_id column to length 500
    op.alter_column('cloud_accounts_v2', 'external_id',
               existing_type=sa.String(length=100),
               type_=sa.String(length=500),
               existing_nullable=True)

def downgrade() -> None:
    op.alter_column('cloud_accounts_v2', 'external_id',
               existing_type=sa.String(length=500),
               type_=sa.String(length=100),
               existing_nullable=True)
    op.alter_column('cloud_accounts', 'external_id',
               existing_type=sa.String(length=500),
               type_=sa.String(length=100),
               existing_nullable=True)
    op.alter_column('cloud_accounts', 'aws_secret_access_key',
               existing_type=sa.String(length=500),
               type_=sa.String(length=100),
               existing_nullable=True)
