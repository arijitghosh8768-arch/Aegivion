"""add batch 3 findings incidents and vulnerabilities

Revision ID: b0003_batch3_findings_incidents
Revises: b0002_batch2_assets
Create Date: 2026-11-08 20:38:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b0003_batch3_findings_incidents'
down_revision: Union[str, None] = 'b0002_batch2_assets'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Modernize findings table
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'findings') THEN
                -- Convert enum columns to VARCHAR(50) for lowercase string compatibility
                ALTER TABLE findings ALTER COLUMN severity TYPE VARCHAR(50) USING severity::text;
                ALTER TABLE findings ALTER COLUMN severity SET DEFAULT 'medium';
                ALTER TABLE findings ALTER COLUMN status TYPE VARCHAR(50) USING status::text;
                ALTER TABLE findings ALTER COLUMN status SET DEFAULT 'open';
                ALTER TABLE findings ALTER COLUMN source TYPE VARCHAR(50) USING source::text;
                ALTER TABLE findings ALTER COLUMN source SET DEFAULT 'cspm';

                -- Add tenant isolation and modernization columns
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_source VARCHAR(100) DEFAULT 'aws_api';
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_collected_at TIMESTAMP WITH TIME ZONE;
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_confidence VARCHAR(50) DEFAULT 'HIGH';
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_quality_score FLOAT DEFAULT 90.0;
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(200);
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS notes JSONB DEFAULT '[]';
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS timeline JSONB DEFAULT '[]';
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(128);
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP WITH TIME ZONE;
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP WITH TIME ZONE;
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS occurrence_count INTEGER DEFAULT 1;
                ALTER TABLE findings ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMP WITH TIME ZONE;

                -- Convert legacy JSON columns to JSONB if needed
                BEGIN
                    ALTER TABLE findings ALTER COLUMN remediation_steps TYPE JSONB USING remediation_steps::jsonb;
                EXCEPTION WHEN OTHERS THEN NULL;
                END;
                BEGIN
                    ALTER TABLE findings ALTER COLUMN evidence TYPE JSONB USING evidence::jsonb;
                EXCEPTION WHEN OTHERS THEN NULL;
                END;
                BEGIN
                    ALTER TABLE findings ALTER COLUMN tags TYPE JSONB USING tags::jsonb;
                EXCEPTION WHEN OTHERS THEN NULL;
                END;
            ELSE
                CREATE TABLE findings (
                    id UUID PRIMARY KEY,
                    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
                    title VARCHAR(300) NOT NULL,
                    description TEXT NOT NULL,
                    severity VARCHAR(50) DEFAULT 'medium' NOT NULL,
                    status VARCHAR(50) DEFAULT 'open' NOT NULL,
                    source VARCHAR(50) DEFAULT 'cspm' NOT NULL,
                    resource_id VARCHAR(200) NOT NULL,
                    resource_name VARCHAR(300) NOT NULL,
                    resource_type VARCHAR(100) NOT NULL,
                    resource_region VARCHAR(100),
                    cloud_provider VARCHAR(50) NOT NULL,
                    rule_id VARCHAR(100) NOT NULL,
                    rule_name VARCHAR(300) NOT NULL,
                    risk_score FLOAT,
                    cvss_score FLOAT,
                    remediation_steps JSONB DEFAULT '{}',
                    evidence JSONB DEFAULT '{}',
                    evidence_source VARCHAR(100) DEFAULT 'aws_api',
                    evidence_collected_at TIMESTAMP WITH TIME ZONE,
                    evidence_confidence VARCHAR(50) DEFAULT 'HIGH',
                    evidence_quality_score FLOAT DEFAULT 90.0,
                    tags JSONB DEFAULT '[]',
                    assigned_to_id UUID REFERENCES users(id) ON DELETE SET NULL,
                    assigned_to VARCHAR(200),
                    notes JSONB DEFAULT '[]',
                    timeline JSONB DEFAULT '[]',
                    resolved_at TIMESTAMP WITH TIME ZONE,
                    resolved_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
                    fingerprint VARCHAR(128),
                    first_seen TIMESTAMP WITH TIME ZONE,
                    last_seen TIMESTAMP WITH TIME ZONE,
                    occurrence_count INTEGER DEFAULT 1,
                    reopened_at TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    is_active BOOLEAN DEFAULT true NOT NULL,
                    created_by UUID,
                    updated_by UUID
                );
            END IF;
        END $$;
    """)
    op.create_index('ix_findings_organization_id', 'findings', ['organization_id'], if_not_exists=True)
    op.create_index('ix_findings_fingerprint', 'findings', ['fingerprint'], if_not_exists=True)
    op.create_index('ix_findings_org_status', 'findings', ['organization_id', 'status'], if_not_exists=True)

    # 2. Incidents table
    op.create_table(
        'incidents',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts_v2.id', ondelete='SET NULL'), nullable=True),
        sa.Column('title', sa.String(length=300), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=50), server_default='medium', nullable=False),
        sa.Column('risk_score', sa.Integer(), server_default='50', nullable=True),
        sa.Column('confidence', sa.Float(), server_default='0.80', nullable=True),
        sa.Column('status', sa.String(length=50), server_default='open', nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finding_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=True),
        sa.Column('asset_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=True),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=True),
        sa.Column('correlation_fingerprint', sa.String(length=255), nullable=True),
        sa.Column('timeline', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=True),
        sa.Column('notes', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=True),
        sa.Column('assigned_to', sa.String(length=200), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_incidents_org_id', 'incidents', ['organization_id'], if_not_exists=True)
    op.create_index('ix_incidents_status', 'incidents', ['organization_id', 'status'], if_not_exists=True)
    op.create_index('ix_incidents_fingerprint', 'incidents', ['correlation_fingerprint'], if_not_exists=True)

    # 3. Vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('affected_asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_assets.id', ondelete='CASCADE'), nullable=True),
        sa.Column('cve_id', sa.String(length=50), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('in_cisa_kev', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cwe_id', sa.String(length=50), nullable=True),
        sa.Column('capec_id', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_vulnerabilities_org_id', 'vulnerabilities', ['organization_id'], if_not_exists=True)
    op.create_index('ix_vulnerabilities_cve_id', 'vulnerabilities', ['cve_id'], if_not_exists=True)
    op.create_index('ix_vulnerabilities_asset_id', 'vulnerabilities', ['affected_asset_id'], if_not_exists=True)


def downgrade() -> None:
    # 1. Drop vulnerabilities
    op.drop_index('ix_vulnerabilities_asset_id', table_name='vulnerabilities', if_exists=True)
    op.drop_index('ix_vulnerabilities_cve_id', table_name='vulnerabilities', if_exists=True)
    op.drop_index('ix_vulnerabilities_org_id', table_name='vulnerabilities', if_exists=True)
    op.drop_table('vulnerabilities', if_exists=True)

    # 2. Drop incidents
    op.drop_index('ix_incidents_fingerprint', table_name='incidents', if_exists=True)
    op.drop_index('ix_incidents_status', table_name='incidents', if_exists=True)
    op.drop_index('ix_incidents_org_id', table_name='incidents', if_exists=True)
    op.drop_table('incidents', if_exists=True)

    # 3. Revert findings additions
    op.drop_index('ix_findings_org_status', table_name='findings', if_exists=True)
    op.drop_index('ix_findings_fingerprint', table_name='findings', if_exists=True)
    op.drop_index('ix_findings_organization_id', table_name='findings', if_exists=True)

    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'findings') THEN
                ALTER TABLE findings DROP COLUMN IF EXISTS organization_id;
                ALTER TABLE findings DROP COLUMN IF EXISTS evidence_source;
                ALTER TABLE findings DROP COLUMN IF EXISTS evidence_collected_at;
                ALTER TABLE findings DROP COLUMN IF EXISTS evidence_confidence;
                ALTER TABLE findings DROP COLUMN IF EXISTS evidence_quality_score;
                ALTER TABLE findings DROP COLUMN IF EXISTS assigned_to;
                ALTER TABLE findings DROP COLUMN IF EXISTS notes;
                ALTER TABLE findings DROP COLUMN IF EXISTS timeline;
                ALTER TABLE findings DROP COLUMN IF EXISTS fingerprint;
                ALTER TABLE findings DROP COLUMN IF EXISTS first_seen;
                ALTER TABLE findings DROP COLUMN IF EXISTS last_seen;
                ALTER TABLE findings DROP COLUMN IF EXISTS occurrence_count;
                ALTER TABLE findings DROP COLUMN IF EXISTS reopened_at;
            END IF;
        END $$;
    """)

