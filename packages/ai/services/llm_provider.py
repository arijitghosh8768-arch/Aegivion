import os
import time
from abc import ABC, abstractmethod
from typing import Dict, Any

class LLMException(Exception):
    def __init__(self, message: str, status_code: str = "error"):
        super().__init__(message)
        self.status_code = status_code

class LLMProvider(ABC):
    @abstractmethod
    def generate(self, context: str) -> str:
        """Generates analysis for the context."""
        pass

    def call_with_retry(self, fn, *args, max_retries: int = 3, initial_delay: float = 1.0, **kwargs):
        """Standard retry logic with exponential backoff and limits."""
        delay = initial_delay
        for attempt in range(max_retries):
            try:
                return fn(*args, **kwargs)
            except LLMException as e:
                # If invalid credentials/API key, don't retry
                if e.status_code == "invalid_api_key":
                    raise e
                if attempt == max_retries - 1:
                    raise e
                print(f"LLM Call failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)
                delay *= 2
            except Exception as e:
                if attempt == max_retries - 1:
                    raise LLMException(f"LLM Provider internal error: {str(e)}")
                time.sleep(delay)
                delay *= 2

class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.model = model or os.getenv("LLM_MODEL", "gpt-4-turbo")

    def generate(self, context: str) -> str:
        if not self.api_key:
            raise LLMException("OpenAI API key missing", "invalid_api_key")
            
        def _execute():
            # In a real app: client.chat.completions.create(...)
            # Let's mock a successful OpenAI completion conforming to frozen schema
            return "OpenAI analysis complete"
            
        return self.call_with_retry(_execute)

class GeminiProvider(LLMProvider):
    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.model = model or os.getenv("LLM_MODEL", "gemini-1.5-pro")

    def generate(self, context: str) -> str:
        if not self.api_key:
            raise LLMException("Gemini API key missing", "invalid_api_key")
            
        def _execute():
            # Mock Gemini reasoning response conforming to the ai-analysis schema
            return "Gemini reasoning complete"
            
        return self.call_with_retry(_execute)

class LocalProvider(LLMProvider):
    def __init__(self, model: str = None):
        self.model = model or os.getenv("LLM_MODEL", "llama3")

    def generate(self, context: str) -> str:
        # Mock local provider response
        return "Local reasoning complete"

def get_llm_provider() -> LLMProvider:
    provider_name = os.getenv("LLM_PROVIDER", "local").lower()
    if provider_name == "openai":
        return OpenAIProvider()
    elif provider_name == "gemini":
        return GeminiProvider()
    else:
        return LocalProvider()
