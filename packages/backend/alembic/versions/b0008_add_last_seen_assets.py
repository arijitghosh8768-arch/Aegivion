"""add last seen to cloud assets

Revision ID: b0008_add_last_seen_assets
Revises: b0007_add_aws_role_to_cloud
Create Date: 2026-11-08 23:05:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'b0008_add_last_seen_assets'
down_revision: Union[str, None] = 'b0007_add_aws_role_to_cloud'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'cloud_assets',
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        'cloud_assets',
        sa.Column('current_hash', sa.String(length=64), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('cloud_assets', 'current_hash')
    op.drop_column('cloud_assets', 'last_seen_at')

