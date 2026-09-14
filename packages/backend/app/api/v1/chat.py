from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, Request
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import json

from ai.services.llm_provider import get_llm_provider
from ai.services.rag import rag_retriever
from app.core.rate_limit import limiter

router = APIRouter()

class ChatMessage(BaseModel):
    role: str # "user" or "assistant"
    content: str
    
class ChatRequest(BaseModel):
    message: str
    finding_id: Optional[str] = None
    asset_id: Optional[str] = None
    history: List[ChatMessage] = Field(default_factory=list)

class ChatResponse(BaseModel):
    response: str
    observed: List[str] = Field(default_factory=list)
    inferred: List[str] = Field(default_factory=list)
    unknown: List[str] = Field(default_factory=list)
    declined: bool = False
    
def build_chat_prompt(request: ChatRequest, context_data: Dict) -> str:
    system_prompt = """You are Aegivion AI, a specialized cloud security assistant.
You are helping the user understand a specific security context.

GROUNDING RULES:
1. ONLY answer questions based on the provided context, evidence, and retrieved threat intelligence.
2. If the user asks a question that CANNOT be answered using the provided context, you MUST decline to answer. Start your response with "DECLINE:".
3. Distinguish clearly between observed facts, inferred risks, and unknown details.

RESPONSE FORMAT:
If you decline, output exactly:
{
    "declined": true,
    "response": "I do not have evidence or context to answer that question.",
    "observed": [], "inferred": [], "unknown": []
}

If you answer, output a JSON object:
{
    "declined": false,
    "response": "Your conversational answer...",
    "observed": ["Fact 1"],
    "inferred": ["Inference 1"],
    "unknown": ["Unknown 1"]
}
"""
    
    context_str = json.dumps(context_data, indent=2)
    prompt = f"{system_prompt}\n\nCONTEXT:\n{context_str}\n\nCONVERSATION HISTORY:\n"
    
    for msg in request.history:
        prompt += f"{msg.role.upper()}: {msg.content}\n"
        
    prompt += f"USER: {request.message}\nASSISTANT (Output JSON ONLY):"
    return prompt

import time
import structlog
from app.core.metrics import api_requests_total, ai_requests_total, api_request_duration_seconds, ai_request_duration_seconds
from app.api.deps import get_current_user
from app.models.user import User

logger = structlog.get_logger(__name__)

from sqlalchemy.orm import Session
from app.database import get_db
from app.models.org_settings import OrgSettings

@router.post("/chat", response_model=ChatResponse)
@limiter.limit("10/minute")
async def chat_endpoint(request_obj: Request, request: ChatRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    start_time = time.time()
    api_requests_total.labels(method="POST", endpoint="/api/v1/chat").inc()
    ai_requests_total.inc()
    
    # TENANT ISOLATION: Ensure the user belongs to an org and the finding/asset belongs to that org.
    # In a full implementation, we'd query the DB for the asset/finding and enforce `org_id == current_user.org_id`.
    # For now, we simulate this security check.
    user_org_id = current_user.get("organization_id") if isinstance(current_user, dict) else getattr(current_user, "organization_id", None)
    if not user_org_id:
        raise HTTPException(status_code=403, detail="User does not belong to an organization")
        
    settings = db.query(OrgSettings).filter(OrgSettings.organization_id == str(user_org_id)).first()
    if settings and not settings.ai_features_enabled:
        raise HTTPException(status_code=403, detail="AI features are not enabled for your organization")

    logger.info("processing_chat_request", user_id=current_user.get("id") if isinstance(current_user, dict) else getattr(current_user, "id"), org_id=user_org_id, finding_id=request.finding_id)

    context_data = {
        "finding_id": request.finding_id,
        "asset_id": request.asset_id,
        "org_id": current_user.org_id,
        "note": "This is simulated context for the chat grounding."
    }
    
    # Retrieve RAG context if applicable
    if request.finding_id:
        rag_data = rag_retriever.retrieve_security_knowledge(
            finding_id=request.finding_id,
            provider="aws",
            finding_type="general",
            finding_metadata={}
        )
        context_data["threat_intelligence"] = rag_data.get("relevant_knowledge", [])
        
    prompt = build_chat_prompt(request, context_data)
    provider = get_llm_provider()
    
    try:
        response_text = provider.generate(prompt)
        parsed = json.loads(response_text)
        
        duration = time.time() - start_time
        api_request_duration_seconds.labels(method="POST", endpoint="/api/v1/chat").observe(duration)
        ai_request_duration_seconds.observe(duration)
        
        logger.info("chat_request_successful", duration=duration)
        
        return {
            "response": parsed.get("response", "I could not generate a response."),
            "observed": parsed.get("observed", []),
            "inferred": parsed.get("inferred", []),
            "unknown": parsed.get("unknown", []),
            "declined": parsed.get("declined", False)
        }
    except Exception as e:
        logger.error("chat_request_failed", error=str(e), exc_info=True)
        # Fallback if model fails to output valid JSON
        if "DECLINE:" in str(e):
            return {
                "response": "I do not have evidence or context to answer that question.",
                "observed": [],
                "inferred": [],
                "unknown": [],
                "declined": True
            }
            
        return {
            "response": "I encountered an error processing your request.",
            "observed": [],
            "inferred": [],
            "unknown": [],
            "declined": False
        }
