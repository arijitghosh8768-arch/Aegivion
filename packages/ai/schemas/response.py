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
