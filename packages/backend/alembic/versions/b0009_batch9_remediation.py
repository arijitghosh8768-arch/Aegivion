"""add batch 9 remediation lifecycle

Revision ID: b0009_batch9_remediation
Revises: b0008_add_last_seen_assets
Create Date: 2026-11-09 00:27:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b0009_batch9_remediation'
down_revision: Union[str, None] = 'b0008_add_last_seen_assets'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. remediation_plans table
    op.create_table(
        'remediation_plans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('resource_id', sa.String(length=255), nullable=False, index=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='PENDING_APPROVAL', index=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('idempotency_key', sa.String(length=128), nullable=True, unique=True, index=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 2. remediation_actions table
    op.create_table(
        'remediation_actions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('plan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('remediation_plans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('action_type', sa.String(length=100), nullable=False),
        sa.Column('parameters', postgresql.JSONB(), server_default='{}', nullable=False),
        sa.Column('rollback_payload', postgresql.JSONB(), server_default='{}', nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='PENDING', index=True),
        sa.Column('aws_request_id', sa.String(length=128), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 3. remediation_audit_logs table
    op.create_table(
        'remediation_audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('plan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('remediation_plans.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('actor_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('details', postgresql.JSONB(), server_default='{}', nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('remediation_audit_logs')
    op.drop_table('remediation_actions')
    op.drop_table('remediation_plans')

