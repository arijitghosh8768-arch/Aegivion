"""add batch 5 security events table

Revision ID: b0005_batch5_security_events
Revises: b0004_batch4_compliance_reports
Create Date: 2026-11-08 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b0005_batch5_security_events'
down_revision: Union[str, None] = 'b0004_batch4_compliance_reports'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Security Events Table
    op.create_table(
        'security_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts_v2.id', ondelete='SET NULL'), nullable=True),
        sa.Column('event_id', sa.String(length=100), nullable=True),
        sa.Column('provider', sa.String(length=50), server_default='aws', nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('action', sa.String(length=200), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('actor', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=True),
        sa.Column('target', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=True),
        sa.Column('source', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=True),
        sa.Column('native_event_id', sa.String(length=200), nullable=True),
        sa.Column('raw_event_reference', sa.Text(), nullable=True),
        sa.Column('event_fingerprint', sa.String(length=128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_security_events_org_id', 'security_events', ['organization_id'], if_not_exists=True)
    op.create_index('ix_security_events_org_fingerprint', 'security_events', ['organization_id', 'event_fingerprint'], if_not_exists=True)
    op.create_index('ix_security_events_org_timestamp', 'security_events', ['organization_id', sa.text('timestamp DESC')], if_not_exists=True)
    op.create_index('ix_security_events_type', 'security_events', ['organization_id', 'event_type'], if_not_exists=True)


def downgrade() -> None:
    # 1. Drop Indexes
    op.drop_index('ix_security_events_type', table_name='security_events', if_exists=True)
    op.drop_index('ix_security_events_org_timestamp', table_name='security_events', if_exists=True)
    op.drop_index('ix_security_events_org_fingerprint', table_name='security_events', if_exists=True)
    op.drop_index('ix_security_events_org_id', table_name='security_events', if_exists=True)

    # 2. Drop Table
    op.drop_table('security_events', if_exists=True)

