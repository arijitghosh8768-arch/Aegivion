from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AIResponse(BaseModel):
    query: str
    summary: str
    risk_level: RiskLevel
    explanation: str
    recommendation: str
    references: List[str] = Field(default_factory=list)
    confidence_score: float = Field(ge=0, le=1)
    tokens_used: int
    processing_time_ms: int
    
class StreamingChunk(BaseModel):
    chunk_type: str  # "thought", "finding", "recommendation", "complete"
    content: str
    metadata: Optional[Dict[str, Any]] = None

class ExplainResponse(BaseModel):
    finding_id: str
    summary: str
    observed: List[str] = Field(description="Explicitly observed facts based purely on available evidence.")
    inferred: List[str] = Field(description="Inferred risks, potential implications, or unconfirmed hypotheses.")
    unknown: List[str] = Field(description="Missing context or details that cannot be determined from evidence.")
    recommendations: List[str]
    confidence_score: float = Field(ge=0, le=1)
