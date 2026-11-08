"""add batch 2 cloud and asset tables

Revision ID: b0002_batch2_assets
Revises: b0001_batch1_identity
Create Date: 2026-11-05 22:20:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b0002_batch2_assets'
down_revision: Union[str, None] = 'b0001_batch1_identity'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # 0. Alter legacy 8f0a cloud_accounts table if it exists
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'cloud_accounts') THEN
                ALTER TABLE cloud_accounts ALTER COLUMN status TYPE VARCHAR(50) USING status::text;
                ALTER TABLE cloud_accounts ALTER COLUMN status SET DEFAULT 'connected';
                ALTER TABLE cloud_accounts ALTER COLUMN provider TYPE VARCHAR(50) USING provider::text;
                ALTER TABLE cloud_accounts ALTER COLUMN provider SET DEFAULT 'AWS';
            END IF;
        END $$;
    """)

    # 1. Cloud Accounts
    op.create_table(
        'cloud_accounts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('provider', sa.String(length=50), server_default='AWS', nullable=False),
        sa.Column('aws_access_key_id', sa.String(length=100), nullable=True),
        sa.Column('aws_secret_access_key', sa.String(length=100), nullable=True),
        sa.Column('aws_region', sa.String(length=50), server_default='ap-south-1', nullable=True),
        sa.Column('status', sa.String(length=50), server_default='connected', nullable=True),
        sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_cloud_accounts_org_id', 'cloud_accounts', ['organization_id'], if_not_exists=True)

    # 2. Cloud Accounts V2
    op.create_table(
        'cloud_accounts_v2',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('provider', sa.String(length=50), server_default='aws', nullable=False),
        sa.Column('account_id', sa.String(length=100), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=True),
        sa.Column('account_name', sa.String(length=200), nullable=True),
        sa.Column('default_region', sa.String(length=50), server_default='ap-south-1', nullable=True),
        sa.Column('connection_status', sa.String(length=50), server_default='disconnected', nullable=True),
        sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.UniqueConstraint('organization_id', 'provider', 'account_id', name='uq_cloud_account_v2'),
        if_not_exists=True
    )
    op.create_index('ix_cloud_accounts_v2_org', 'cloud_accounts_v2', ['organization_id'], if_not_exists=True)

    # 3. Cloud Assets
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'cloud_assets') THEN
                ALTER TABLE cloud_assets ADD COLUMN IF NOT EXISTS environment VARCHAR(50) DEFAULT 'DEVELOPMENT';
                ALTER TABLE cloud_assets ADD COLUMN IF NOT EXISTS owner VARCHAR(100) DEFAULT 'UNKNOWN';
                ALTER TABLE cloud_assets ADD COLUMN IF NOT EXISTS department VARCHAR(100) DEFAULT 'UNKNOWN';
                ALTER TABLE cloud_assets ADD COLUMN IF NOT EXISTS application VARCHAR(100) DEFAULT 'UNKNOWN';
                ALTER TABLE cloud_assets ADD COLUMN IF NOT EXISTS data_classification VARCHAR(50) DEFAULT 'UNKNOWN';
                ALTER TABLE cloud_assets ADD COLUMN IF NOT EXISTS business_criticality VARCHAR(50) DEFAULT 'UNKNOWN';
                ALTER TABLE cloud_assets ADD COLUMN IF NOT EXISTS internet_exposed BOOLEAN DEFAULT false;
                ALTER TABLE cloud_assets ADD COLUMN IF NOT EXISTS importance_score FLOAT DEFAULT 0.0;
                -- Drop old foreign key constraint pointing to cloud_accounts if present
                ALTER TABLE cloud_assets DROP CONSTRAINT IF EXISTS cloud_assets_account_id_fkey;
                -- Allow account_id to reference cloud_accounts_v2 or nullable
                ALTER TABLE cloud_assets ALTER COLUMN account_id DROP NOT NULL;
                ALTER TABLE cloud_assets ALTER COLUMN provider TYPE VARCHAR(50) USING provider::text;
                -- Re-add FK constraint to cloud_accounts_v2 if not already pointing to it
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.table_constraints 
                    WHERE constraint_name = 'cloud_assets_account_id_v2_fkey'
                ) THEN
                    ALTER TABLE cloud_assets ADD CONSTRAINT cloud_assets_account_id_v2_fkey 
                    FOREIGN KEY (account_id) REFERENCES cloud_accounts_v2(id) ON DELETE CASCADE;
                END IF;
            END IF;
        END $$;
    """)
    op.create_table(
        'cloud_assets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts_v2.id', ondelete='CASCADE'), nullable=True),
        sa.Column('resource_id', sa.String(length=300), nullable=False),
        sa.Column('name', sa.String(length=300), nullable=False),
        sa.Column('type', sa.String(length=100), nullable=False),
        sa.Column('region', sa.String(length=100), nullable=True),
        sa.Column('provider', sa.String(length=50), server_default='AWS', nullable=False),
        sa.Column('metadata_json', sa.JSON(), server_default='{}', nullable=True),
        sa.Column('environment', sa.String(length=50), server_default='DEVELOPMENT', nullable=True),
        sa.Column('owner', sa.String(length=100), server_default='UNKNOWN', nullable=True),
        sa.Column('department', sa.String(length=100), server_default='UNKNOWN', nullable=True),
        sa.Column('application', sa.String(length=100), server_default='UNKNOWN', nullable=True),
        sa.Column('data_classification', sa.String(length=50), server_default='UNKNOWN', nullable=True),
        sa.Column('business_criticality', sa.String(length=50), server_default='UNKNOWN', nullable=True),
        sa.Column('internet_exposed', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.Column('importance_score', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_cloud_assets_resource_id', 'cloud_assets', ['resource_id'], if_not_exists=True)
    op.create_index('ix_cloud_assets_type', 'cloud_assets', ['type'], if_not_exists=True)
    op.create_index('ix_cloud_assets_account_id', 'cloud_assets', ['account_id'], if_not_exists=True)

    # 4. Detailed Asset Tables (EC2, S3, IAM, Security Groups)
    op.create_table(
        'ec2_instances',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_assets.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('instance_id', sa.String(length=100), nullable=False),
        sa.Column('state', sa.String(length=50), nullable=False),
        sa.Column('public_ip', sa.String(length=50), nullable=True),
        sa.Column('private_ip', sa.String(length=50), nullable=True),
        sa.Column('instance_type', sa.String(length=50), nullable=False),
        sa.Column('security_groups', sa.JSON(), server_default='[]', nullable=True),
        sa.Column('has_public_ip', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )

    op.create_table(
        's3_buckets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_assets.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('bucket_name', sa.String(length=200), nullable=False),
        sa.Column('arn', sa.String(length=300), nullable=False),
        sa.Column('is_public', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.Column('encryption_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.Column('versioning_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )

    op.create_table(
        'iam_users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_assets.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('username', sa.String(length=200), nullable=False),
        sa.Column('arn', sa.String(length=300), nullable=False),
        sa.Column('mfa_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.Column('is_admin', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.Column('access_keys_age_days', sa.Integer(), server_default='0', nullable=True),
        sa.Column('last_active', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )

    op.create_table(
        'security_groups',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_assets.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('group_id', sa.String(length=100), nullable=False),
        sa.Column('group_name', sa.String(length=200), nullable=False),
        sa.Column('vpc_id', sa.String(length=100), nullable=True),
        sa.Column('ingress_rules', sa.JSON(), server_default='[]', nullable=True),
        sa.Column('egress_rules', sa.JSON(), server_default='[]', nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )

    # 5. Asset Relationships
    op.create_table(
        'asset_relationships',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('source_asset_id', sa.String(length=300), nullable=False),
        sa.Column('target_asset_id', sa.String(length=300), nullable=False),
        sa.Column('relationship_type', sa.String(length=100), nullable=False),
        sa.Column('account_id', sa.String(length=100), nullable=True),
        sa.Column('region', sa.String(length=100), nullable=True),
        sa.Column('evidence', sa.JSON(), server_default='{}', nullable=True),
        sa.Column('confidence', sa.String(length=50), server_default='UNKNOWN', nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_asset_relationships_org', 'asset_relationships', ['organization_id'], if_not_exists=True)
    op.create_index('ix_asset_relationships_source', 'asset_relationships', ['source_asset_id'], if_not_exists=True)
    op.create_index('ix_asset_relationships_target', 'asset_relationships', ['target_asset_id'], if_not_exists=True)

    # 6. Scan Jobs
    op.create_table(
        'scan_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts.id', ondelete='CASCADE'), nullable=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='queued', nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('assets_discovered', sa.Integer(), server_default='0', nullable=True),
        sa.Column('findings_generated', sa.Integer(), server_default='0', nullable=True),
        sa.Column('collector_status', sa.JSON(), server_default='{}', nullable=True),
        sa.Column('error_summary', sa.String(length=500), nullable=True),
        sa.Column('region', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_scan_jobs_org', 'scan_jobs', ['organization_id'], if_not_exists=True)

def downgrade() -> None:
    op.drop_table('scan_jobs', if_exists=True)
    op.drop_table('asset_relationships', if_exists=True)
    op.drop_table('security_groups', if_exists=True)
    op.drop_table('iam_users', if_exists=True)
    op.drop_table('s3_buckets', if_exists=True)
    op.drop_table('ec2_instances', if_exists=True)
    op.drop_table('cloud_assets', if_exists=True)
    op.drop_table('cloud_accounts_v2', if_exists=True)
    op.drop_table('cloud_accounts', if_exists=True)
