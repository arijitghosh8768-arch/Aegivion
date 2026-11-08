"""add batch 1 identity tables

Revision ID: b0001_batch1_identity
Revises: a0001_add_knowledge_models
Create Date: 2026-11-05 22:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b0001_batch1_identity'
down_revision: Union[str, None] = 'a0001_add_knowledge_models'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # 1. Organizations
    # In case organizations already exists from 810b, add any missing Batch 1 columns and alter enums to varchar
    op.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'organizations') THEN
                CREATE TABLE organizations (
                    id UUID PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    slug VARCHAR(200) NOT NULL,
                    industry VARCHAR(100),
                    subscription_plan VARCHAR(50) DEFAULT 'free',
                    owner_id UUID,
                    settings JSON DEFAULT '{}',
                    trial_ends_at TIMESTAMP WITH TIME ZONE,
                    subscription_ends_at TIMESTAMP WITH TIME ZONE,
                    max_users INTEGER DEFAULT 5,
                    max_projects INTEGER DEFAULT 1,
                    features JSON,
                    security_policy JSON,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    is_active BOOLEAN DEFAULT true NOT NULL,
                    created_by UUID,
                    updated_by UUID
                );
            ELSE
                ALTER TABLE organizations ADD COLUMN IF NOT EXISTS security_policy JSON;
                -- Convert subscription_plan enum to VARCHAR(50) if necessary
                ALTER TABLE organizations ALTER COLUMN subscription_plan TYPE VARCHAR(50) USING subscription_plan::text;
                ALTER TABLE organizations ALTER COLUMN subscription_plan SET DEFAULT 'free';
            END IF;
        END $$;
    """)
    op.create_index('ix_organizations_slug', 'organizations', ['slug'], unique=True, if_not_exists=True)

    # 2. Roles
    op.create_table(
        'roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )

    # 3. Users
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') THEN
                ALTER TABLE users ALTER COLUMN status TYPE VARCHAR(50) USING status::text;
                ALTER TABLE users ALTER COLUMN status SET DEFAULT 'pending_verification';
            END IF;
        END $$;
    """)
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('first_name', sa.String(length=100), nullable=False),
        sa.Column('last_name', sa.String(length=100), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('phone', sa.String(length=20), nullable=True),
        sa.Column('status', sa.String(length=50), server_default='pending_verification', nullable=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('email_verified', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('mfa_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.Column('mfa_secret', sa.String(length=255), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_ip', sa.String(length=45), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), server_default='0', nullable=True),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True, if_not_exists=True)
    op.create_index('ix_users_org_status', 'users', ['organization_id', 'status'], if_not_exists=True)

    # 4. Organization Members
    op.create_table(
        'organization_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role', sa.String(length=50), server_default='MEMBER', nullable=False),
        sa.Column('status', sa.String(length=50), server_default='ACTIVE', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.UniqueConstraint('organization_id', 'user_id', name='uq_org_user'),
        if_not_exists=True
    )
    op.create_index('ix_org_members_user', 'organization_members', ['user_id'], if_not_exists=True)
    op.create_index('ix_org_members_org', 'organization_members', ['organization_id'], if_not_exists=True)

    # 5. Sessions
    op.create_table(
        'sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('session_token_hash', sa.String(length=255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('ip_hash_or_safe_metadata', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_sessions_token_hash', 'sessions', ['session_token_hash'], if_not_exists=True)
    op.create_index('ix_sessions_user_id', 'sessions', ['user_id'], if_not_exists=True)

    # 6. Invitations
    op.create_table(
        'invitations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='SET NULL'), nullable=True),
        sa.Column('invited_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('status', sa.String(length=50), server_default='PENDING', nullable=False),
        sa.Column('token', sa.String(length=255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_invitations_token', 'invitations', ['token'], unique=True, if_not_exists=True)
    op.create_index('ix_invitations_org_email', 'invitations', ['org_id', 'email'], if_not_exists=True)

def downgrade() -> None:
    op.execute('DROP TABLE IF EXISTS invitations CASCADE;')
    op.execute('DROP TABLE IF EXISTS sessions CASCADE;')
    op.execute('DROP TABLE IF EXISTS organization_members CASCADE;')
    op.execute('DROP TABLE IF EXISTS users CASCADE;')
    op.execute('DROP TABLE IF EXISTS roles CASCADE;')
    op.execute('DROP TABLE IF EXISTS organizations CASCADE;')

