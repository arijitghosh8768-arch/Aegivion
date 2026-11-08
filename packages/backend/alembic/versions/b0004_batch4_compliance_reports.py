"""add batch 4 compliance and reports tables

Revision ID: b0004_batch4_compliance_reports
Revises: b0003_batch3_findings_incidents
Create Date: 2026-11-08 20:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b0004_batch4_compliance_reports'
down_revision: Union[str, None] = 'b0003_batch3_findings_incidents'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Compliance Results
    op.create_table(
        'compliance_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts_v2.id', ondelete='SET NULL'), nullable=True),
        sa.Column('control_code', sa.String(length=100), nullable=False),
        sa.Column('framework_id', sa.String(length=100), server_default='CIS_AWS_v3', nullable=False),
        sa.Column('title', sa.String(length=300), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('severity', sa.String(length=50), server_default='high', nullable=True),
        sa.Column('status', sa.String(length=50), server_default='NOT_ASSESSED', nullable=False),
        sa.Column('affected_resources', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=True),
        sa.Column('evidence_refs', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=True),
        sa.Column('finding_refs', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=True),
        sa.Column('assessed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scan_id', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_compliance_results_org_id', 'compliance_results', ['organization_id'], if_not_exists=True)
    op.create_index('ix_compliance_results_org_control', 'compliance_results', ['organization_id', 'control_code'], if_not_exists=True)
    op.create_index('ix_compliance_results_framework', 'compliance_results', ['organization_id', 'framework_id', 'status'], if_not_exists=True)

    # 2. Security Posture Snapshots
    op.create_table(
        'security_snapshots',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts_v2.id', ondelete='SET NULL'), nullable=True),
        sa.Column('scan_id', sa.String(length=100), nullable=True),
        sa.Column('snapshot_version', sa.String(length=50), server_default='0.4.0', nullable=True),
        sa.Column('coverage_status', sa.String(length=50), server_default='PARTIAL', nullable=True),
        sa.Column('assets', postgresql.JSONB(astext_type=sa.Text()), server_default='{"total": 0, "high_risk": 0}', nullable=True),
        sa.Column('findings', postgresql.JSONB(astext_type=sa.Text()), server_default='{"critical": 0, "high": 0, "medium": 0, "low": 0}', nullable=True),
        sa.Column('incidents', postgresql.JSONB(astext_type=sa.Text()), server_default='{"open": 0, "investigating": 0}', nullable=True),
        sa.Column('attack_paths', postgresql.JSONB(astext_type=sa.Text()), server_default='{"critical": 0, "high": 0}', nullable=True),
        sa.Column('remediation', postgresql.JSONB(astext_type=sa.Text()), server_default='{"open": 0, "verified": 0}', nullable=True),
        sa.Column('compliance', postgresql.JSONB(astext_type=sa.Text()), server_default='{"pass": 0, "fail": 0, "not_assessed": 0}', nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_security_snapshots_org_id', 'security_snapshots', ['organization_id'], if_not_exists=True)
    op.create_index('ix_security_snapshots_org_created', 'security_snapshots', ['organization_id', 'created_at'], if_not_exists=True)

    # 3. Generated Reports
    op.create_table(
        'generated_reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts_v2.id', ondelete='SET NULL'), nullable=True),
        sa.Column('snapshot_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('security_snapshots.id', ondelete='SET NULL'), nullable=True),
        sa.Column('report_type', sa.String(length=50), server_default='EXECUTIVE', nullable=False),
        sa.Column('status', sa.String(length=50), server_default='COMPLETED', nullable=False),
        sa.Column('title', sa.String(length=300), nullable=True),
        sa.Column('content', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_generated_reports_org_id', 'generated_reports', ['organization_id'], if_not_exists=True)
    op.create_index('ix_generated_reports_org_created', 'generated_reports', ['organization_id', 'created_at'], if_not_exists=True)

    # 4. Asset Snapshots
    op.create_table(
        'asset_snapshots',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts_v2.id', ondelete='SET NULL'), nullable=True),
        sa.Column('asset_id', sa.String(length=300), nullable=False),
        sa.Column('version_number', sa.Integer(), server_default='1', nullable=False),
        sa.Column('configuration', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=True),
        sa.Column('configuration_hash', sa.String(length=64), nullable=False),
        sa.Column('scan_id', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_asset_snapshots_org_id', 'asset_snapshots', ['organization_id'], if_not_exists=True)
    op.create_index('ix_asset_snapshots_asset_ver', 'asset_snapshots', ['organization_id', 'asset_id', 'version_number'], if_not_exists=True)
    op.create_index('ix_asset_snapshots_hash', 'asset_snapshots', ['configuration_hash'], if_not_exists=True)

    # 5. Security Risk Snapshots
    op.create_table(
        'security_risk_snapshots',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cloud_account_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('cloud_accounts_v2.id', ondelete='SET NULL'), nullable=True),
        sa.Column('scan_id', sa.String(length=100), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('asset_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('finding_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('critical_findings', sa.Integer(), server_default='0', nullable=True),
        sa.Column('high_findings', sa.Integer(), server_default='0', nullable=True),
        sa.Column('medium_findings', sa.Integer(), server_default='0', nullable=True),
        sa.Column('low_findings', sa.Integer(), server_default='0', nullable=True),
        sa.Column('open_incidents', sa.Integer(), server_default='0', nullable=True),
        sa.Column('critical_attack_paths', sa.Integer(), server_default='0', nullable=True),
        sa.Column('high_attack_paths', sa.Integer(), server_default='0', nullable=True),
        sa.Column('compliance_pass_rate', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('overall_risk', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('data_source', sa.String(length=50), server_default='REAL', nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        if_not_exists=True
    )
    op.create_index('ix_security_risk_snapshots_org_id', 'security_risk_snapshots', ['organization_id'], if_not_exists=True)
    op.create_index('ix_security_risk_snapshots_org_time', 'security_risk_snapshots', ['organization_id', 'timestamp'], if_not_exists=True)


def downgrade() -> None:
    # 5. Security Risk Snapshots
    op.drop_index('ix_security_risk_snapshots_org_time', table_name='security_risk_snapshots', if_exists=True)
    op.drop_index('ix_security_risk_snapshots_org_id', table_name='security_risk_snapshots', if_exists=True)
    op.drop_table('security_risk_snapshots', if_exists=True)

    # 4. Asset Snapshots
    op.drop_index('ix_asset_snapshots_hash', table_name='asset_snapshots', if_exists=True)
    op.drop_index('ix_asset_snapshots_asset_ver', table_name='asset_snapshots', if_exists=True)
    op.drop_index('ix_asset_snapshots_org_id', table_name='asset_snapshots', if_exists=True)
    op.drop_table('asset_snapshots', if_exists=True)

    # 3. Generated Reports
    op.drop_index('ix_generated_reports_org_created', table_name='generated_reports', if_exists=True)
    op.drop_index('ix_generated_reports_org_id', table_name='generated_reports', if_exists=True)
    op.drop_table('generated_reports', if_exists=True)

    # 2. Security Posture Snapshots
    op.drop_index('ix_security_snapshots_org_created', table_name='security_snapshots', if_exists=True)
    op.drop_index('ix_security_snapshots_org_id', table_name='security_snapshots', if_exists=True)
    op.drop_table('security_snapshots', if_exists=True)

    # 1. Compliance Results
    op.drop_index('ix_compliance_results_framework', table_name='compliance_results', if_exists=True)
    op.drop_index('ix_compliance_results_org_control', table_name='compliance_results', if_exists=True)
    op.drop_index('ix_compliance_results_org_id', table_name='compliance_results', if_exists=True)
    op.drop_table('compliance_results', if_exists=True)

