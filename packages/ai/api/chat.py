import json
import asyncio
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

router = APIRouter()

class ChatRequest(BaseModel):
    message: str

@router.post("/chat/stream")
async def streaming_chat(request: ChatRequest):
    async def generate():
        # Simulate thinking chunk
        yield f"data: {json.dumps({'chunk_type': 'thought', 'content': 'Analyzing your security posture...'})}\n\n"
        await asyncio.sleep(0.5)
        
        # Simulate finding chunk
        yield f"data: {json.dumps({'chunk_type': 'finding', 'content': 'Found 1 public S3 bucket in your configuration'})}\n\n"
        await asyncio.sleep(0.5)
        
        # Simulate recommendation chunk
        yield f"data: {json.dumps({'chunk_type': 'recommendation', 'content': 'Add aws_s3_bucket_public_access_block to block all public access.'})}\n\n"
        await asyncio.sleep(0.5)
        
        # Complete chunk
        yield f"data: {json.dumps({'chunk_type': 'complete', 'content': 'Analysis complete'})}\n\n"
    
    return StreamingResponse(generate(), media_type="text/event-stream")
