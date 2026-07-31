from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import AIConfig

app = FastAPI(
    title="Aegivion AI Service",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
from api.chat import router as chat_router

app.include_router(chat_router, prefix="/api/v1")
@app.get("/")
def read_root():
    return {"service": "ai-service", "status": "running"}

@app.get("/health")
def health():
    return {
        "status": "ready",
        "model": "gemini-3.5-flash",
        "provider": AIConfig.LLM_PROVIDER,
        "service": "ai"
    }
