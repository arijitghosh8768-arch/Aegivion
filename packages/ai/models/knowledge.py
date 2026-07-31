import enum
from sqlalchemy import Column, String, JSON, Integer, ForeignKey, ARRAY, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import BaseModel

class KnowledgeCategory(str, enum.Enum):
    SECURITY_BEST_PRACTICE = "security_best_practice"
    COMPLIANCE = "compliance"
    THREAT = "threat"
    REMEDIATION = "remediation"
    ARCHITECTURE = "architecture"
    GENERAL = "general"

class KnowledgeBase(BaseModel):
    __tablename__ = "knowledge_base"
    
    title = Column(String(300), nullable=False)
    content = Column(String(5000), nullable=False)
    category = Column(Enum(KnowledgeCategory), nullable=False, index=True)
    tags = Column(ARRAY(String), default=[])
    
    # Embedding for vector search (stored as JSON/ARRAY of floats for compatibility)
    embedding = Column(JSON, nullable=True)  
    
    # Metadata
    source = Column(String(200), nullable=True)
    author = Column(String(200), nullable=True)
    
    # References & Related findings
    references = Column(JSON, default=[])
    related_findings = Column(JSON, default=[]) # Stored list of UUIDs
    
    # Versioning
    version = Column(Integer, default=1)
    previous_version_id = Column(UUID(as_uuid=True), nullable=True)

class Conversation(BaseModel):
    __tablename__ = "conversations"
    
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(200), nullable=True)
    messages = Column(JSON, default=[])
    context = Column(JSON, default={})
    
    # Performance metrics
    tokens_used = Column(Integer, default=0)
    response_time_ms = Column(Integer, default=0)
    
    # Relationships
    user = relationship("User")
