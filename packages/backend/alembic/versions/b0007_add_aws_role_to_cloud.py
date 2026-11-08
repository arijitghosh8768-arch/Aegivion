"""add aws role to cloud accounts

Revision ID: b0007_add_aws_role_to_cloud
Revises: b0006_sec_events_org_null
Create Date: 2026-11-08 22:52:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'b0007_add_aws_role_to_cloud'
down_revision: Union[str, None] = 'b0006_sec_events_org_null'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add role_arn and external_id to cloud_accounts
    op.add_column('cloud_accounts', sa.Column('role_arn', sa.String(length=300), nullable=True))
    op.add_column('cloud_accounts', sa.Column('external_id', sa.String(length=100), nullable=True))

    # 2. Add role_arn and external_id to cloud_accounts_v2
    op.add_column('cloud_accounts_v2', sa.Column('role_arn', sa.String(length=300), nullable=True))
    op.add_column('cloud_accounts_v2', sa.Column('external_id', sa.String(length=100), nullable=True))


def downgrade() -> None:
    op.drop_column('cloud_accounts_v2', 'external_id')
    op.drop_column('cloud_accounts_v2', 'role_arn')
    op.drop_column('cloud_accounts', 'external_id')
    op.drop_column('cloud_accounts', 'role_arn')

