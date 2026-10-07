"""add_knowledge_models

Revision ID: a0001_add_knowledge_models
Revises: 9f0bc4b64e3c
Create Date: 2026-10-08 02:25:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from pgvector.sqlalchemy import Vector

# revision identifiers, used by Alembic.
revision = 'a0001_add_knowledge_models'
down_revision = '9f0bc4b64e3c'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Ensure pgvector extension is available in Postgres
    op.execute('CREATE EXTENSION IF NOT EXISTS vector')

    # Create Enums
    knowledge_scope_enum = sa.Enum('GLOBAL', 'ORGANIZATION', 'SYSTEM', name='knowledgescope')
    authority_level_enum = sa.Enum('FRAMEWORK', 'VENDOR', 'ENTERPRISE_POLICY', 'THREAT_INTEL', 'COMMUNITY', name='authoritylevel')
    chunk_status_enum = sa.Enum('ACTIVE', 'QUARANTINED', 'ARCHIVED', name='chunkstatus')

    knowledge_scope_enum.create(op.get_bind(), checkfirst=True)
    authority_level_enum.create(op.get_bind(), checkfirst=True)
    chunk_status_enum.create(op.get_bind(), checkfirst=True)

    # Create knowledge_documents table
    op.create_table('knowledge_documents',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('scope', knowledge_scope_enum, nullable=False),
        sa.Column('authority', authority_level_enum, nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('source_uri', sa.String(), nullable=False),
        sa.Column('version_hash', sa.String(), nullable=False),
        sa.Column('metadata_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_knowledge_documents_organization_id'), 'knowledge_documents', ['organization_id'], unique=False)
    op.create_index(op.f('ix_knowledge_documents_scope'), 'knowledge_documents', ['scope'], unique=False)
    op.create_index(op.f('ix_knowledge_documents_source_uri'), 'knowledge_documents', ['source_uri'], unique=False)

    # Create knowledge_chunks table
    op.create_table('knowledge_chunks',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('document_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('scope', knowledge_scope_enum, nullable=False),
        sa.Column('chunk_index', sa.Integer(), nullable=False),
        sa.Column('text_content', sa.String(), nullable=False),
        sa.Column('content_hash', sa.String(), nullable=False),
        sa.Column('embedding', Vector(384), nullable=True),
        sa.Column('embedding_model', sa.String(), nullable=False),
        sa.Column('token_count', sa.Integer(), nullable=True),
        sa.Column('chunk_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('status', chunk_status_enum, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['document_id'], ['knowledge_documents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_knowledge_chunks_content_hash'), 'knowledge_chunks', ['content_hash'], unique=False)
    op.create_index(op.f('ix_knowledge_chunks_organization_id'), 'knowledge_chunks', ['organization_id'], unique=False)
    op.create_index(op.f('ix_knowledge_chunks_scope'), 'knowledge_chunks', ['scope'], unique=False)
    op.create_index(op.f('ix_knowledge_chunks_status'), 'knowledge_chunks', ['status'], unique=False)

def downgrade() -> None:
    op.drop_index(op.f('ix_knowledge_chunks_status'), table_name='knowledge_chunks')
    op.drop_index(op.f('ix_knowledge_chunks_scope'), table_name='knowledge_chunks')
    op.drop_index(op.f('ix_knowledge_chunks_organization_id'), table_name='knowledge_chunks')
    op.drop_index(op.f('ix_knowledge_chunks_content_hash'), table_name='knowledge_chunks')
    op.drop_table('knowledge_chunks')
    
    op.drop_index(op.f('ix_knowledge_documents_source_uri'), table_name='knowledge_documents')
    op.drop_index(op.f('ix_knowledge_documents_scope'), table_name='knowledge_documents')
    op.drop_index(op.f('ix_knowledge_documents_organization_id'), table_name='knowledge_documents')
    op.drop_table('knowledge_documents')

    sa.Enum('ACTIVE', 'QUARANTINED', 'ARCHIVED', name='chunkstatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum('FRAMEWORK', 'VENDOR', 'ENTERPRISE_POLICY', 'THREAT_INTEL', 'COMMUNITY', name='authoritylevel').drop(op.get_bind(), checkfirst=True)
    sa.Enum('GLOBAL', 'ORGANIZATION', 'SYSTEM', name='knowledgescope').drop(op.get_bind(), checkfirst=True)
