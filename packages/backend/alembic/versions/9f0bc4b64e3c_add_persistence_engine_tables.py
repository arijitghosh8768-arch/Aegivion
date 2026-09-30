"""add_persistence_engine_tables

Revision ID: 9f0bc4b64e3c
Revises: 8f0ab4b64e3b
Create Date: 2026-09-30 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '9f0bc4b64e3c'
down_revision = '8f0ab4b64e3b'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # persistent_events
    op.create_table(
        'persistent_events',
        sa.Column('event_id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('correlation_id', sa.String(), nullable=True),
        sa.Column('event_type', sa.String(), nullable=True),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('source', sa.String(), nullable=True),
        sa.Column('provenance', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('claimed_by', sa.String(), nullable=True),
        sa.Column('fencing_token', sa.String(), nullable=True),
        sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('attempt_count', sa.Integer(), nullable=True),
        sa.Column('last_error', sa.String(), nullable=True),
        sa.Column('requeue_count', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('event_id', 'org_id')
    )
    op.create_index(op.f('ix_persistent_events_status'), 'persistent_events', ['status'], unique=False)
    op.create_index(op.f('ix_persistent_events_claimed_by'), 'persistent_events', ['claimed_by'], unique=False)
    op.create_index(op.f('ix_persistent_events_lease_expires_at'), 'persistent_events', ['lease_expires_at'], unique=False)

    # requeue_records
    op.create_table(
        'requeue_records',
        sa.Column('recovery_id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=True),
        sa.Column('event_id', sa.String(), nullable=True),
        sa.Column('requested_by', sa.String(), nullable=True),
        sa.Column('reason', sa.String(), nullable=True),
        sa.Column('previous_state', sa.String(), nullable=True),
        sa.Column('new_state', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.Column('requeue_count', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('recovery_id')
    )
    op.create_index(op.f('ix_requeue_records_org_id'), 'requeue_records', ['org_id'], unique=False)
    op.create_index(op.f('ix_requeue_records_event_id'), 'requeue_records', ['event_id'], unique=False)

    # agent_states
    op.create_table(
        'agent_states',
        sa.Column('organization_id', sa.String(), nullable=False),
        sa.Column('state', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('organization_id')
    )

    # worker_states
    op.create_table(
        'worker_states',
        sa.Column('worker_id', sa.String(), nullable=False),
        sa.Column('state', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('worker_id')
    )

    # detection_contexts
    op.create_table(
        'detection_contexts',
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('events', sa.JSON(), nullable=True),
        sa.Column('detections', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('org_id')
    )

    # attack_states
    op.create_table(
        'attack_states',
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('state_data', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('org_id')
    )

def downgrade() -> None:
    op.drop_table('attack_states')
    op.drop_table('detection_contexts')
    op.drop_table('worker_states')
    op.drop_table('agent_states')
    op.drop_index(op.f('ix_requeue_records_event_id'), table_name='requeue_records')
    op.drop_index(op.f('ix_requeue_records_org_id'), table_name='requeue_records')
    op.drop_table('requeue_records')
    op.drop_index(op.f('ix_persistent_events_lease_expires_at'), table_name='persistent_events')
    op.drop_index(op.f('ix_persistent_events_claimed_by'), table_name='persistent_events')
    op.drop_index(op.f('ix_persistent_events_status'), table_name='persistent_events')
    op.drop_table('persistent_events')
