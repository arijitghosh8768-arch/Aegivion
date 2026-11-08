"""make security events org nullable

Revision ID: b0006_sec_events_org_null
Revises: b0005_batch5_security_events
Create Date: 2026-11-08 22:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b0006_sec_events_org_null'
down_revision: Union[str, None] = 'b0005_batch5_security_events'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Make organization_id nullable so pre-auth / unknown tenant threats can be logged
    op.alter_column(
        'security_events',
        'organization_id',
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True
    )


def downgrade() -> None:
    op.alter_column(
        'security_events',
        'organization_id',
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False
    )

