import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from pgvector.sqlalchemy import Vector
from .postgres_base import PostgresBase

class KnowledgeScope(str, enum.Enum):
    GLOBAL = "GLOBAL"
    ORGANIZATION = "ORGANIZATION"
    SYSTEM = "SYSTEM"

class AuthorityLevel(str, enum.Enum):
    FRAMEWORK = "FRAMEWORK"
    VENDOR = "VENDOR"
    ENTERPRISE_POLICY = "ENTERPRISE_POLICY"
    THREAT_INTEL = "THREAT_INTEL"
    COMMUNITY = "COMMUNITY"

class ChunkStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"
    ARCHIVED = "ARCHIVED"

class KnowledgeDocument(PostgresBase):
    __tablename__ = "knowledge_documents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    scope = Column(Enum(KnowledgeScope), nullable=False, index=True)
    authority = Column(Enum(AuthorityLevel), nullable=False)
    
    title = Column(String, nullable=False)
    source_uri = Column(String, nullable=False, index=True)
    version_hash = Column(String, nullable=False)
    metadata_json = Column(JSONB, default=dict)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    chunks = relationship("KnowledgeChunk", back_populates="document", cascade="all, delete-orphan")

class KnowledgeChunk(PostgresBase):
    __tablename__ = "knowledge_chunks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id = Column(UUID(as_uuid=True), ForeignKey("knowledge_documents.id", ondelete="CASCADE"), nullable=False)
    
    # Denormalized fields for fast RLS / filtering
    organization_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    scope = Column(Enum(KnowledgeScope), nullable=False, index=True)
    
    chunk_index = Column(Integer, nullable=False)
    text_content = Column(String, nullable=False)
    content_hash = Column(String, nullable=False, index=True)
    
    # Vector store specifics - Fixed dimension to 384 for bge-small-en-v1.5
    embedding = Column(Vector(384), nullable=True) 
    embedding_model = Column(String, nullable=False, default="bge-small-en-v1.5")
    token_count = Column(Integer, default=0)
    
    chunk_metadata = Column(JSONB, default=dict)
    status = Column(Enum(ChunkStatus), nullable=False, default=ChunkStatus.ACTIVE, index=True)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    document = relationship("KnowledgeDocument", back_populates="chunks")
