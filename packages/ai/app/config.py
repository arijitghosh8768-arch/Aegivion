import os

class AIConfig:
    # LLM Choice: Gemini is chosen as our default primary model provider
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")
    
    # API Keys
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    
    # Vector Database URL (Qdrant is the default choice for local development)
    VECTOR_DB_URL = os.getenv("VECTOR_DB_URL", "http://localhost:6333")
    VECTOR_DB_COLLECTION = "aegivion_knowledge_base"

def get_vector_db_client():
    """
    Returns a mock client config or actual connection depending on requirements.
    In Day 1, we return a configuration summary for connection verification.
    """
    return {
        "url": AIConfig.VECTOR_DB_URL,
        "collection": AIConfig.VECTOR_DB_COLLECTION,
        "provider": "Qdrant"
    }
