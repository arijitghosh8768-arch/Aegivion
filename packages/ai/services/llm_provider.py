import os
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

class LLMException(Exception):
    def __init__(self, message: str, status_code: str = "error"):
        super().__init__(message)
        self.status_code = status_code

@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

@dataclass
class LLMResponse:
    text: str
    tokens: Dict[str, int]
    cost: float
    model: str
    provider: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "tokens": self.tokens,
            "cost": self.cost,
            "model": self.model,
            "provider": self.provider
        }

    def __getitem__(self, item):
        return self.to_dict()[item]

    def get(self, item, default=None):
        return self.to_dict().get(item, default)

    # For string compatibility with legacy callers doing `str(res)` or expecting string
    def __str__(self):
        return self.text

class LLMProvider(ABC):
    @abstractmethod
    def generate(self, context: str, system_prompt: Optional[str] = None) -> Union[LLMResponse, str]:
        """Generates analysis for the context."""
        pass

    def call_with_retry(self, fn, *args, max_retries: int = 3, initial_delay: float = 1.0, **kwargs):
        """Standard retry logic with exponential backoff and limits."""
        delay = initial_delay
        for attempt in range(max_retries):
            try:
                return fn(*args, **kwargs)
            except LLMException as e:
                if e.status_code == "invalid_api_key":
                    raise e
                if attempt == max_retries - 1:
                    raise e
                logger.warning(f"LLM Call failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)
                delay *= 2
            except Exception as e:
                if attempt == max_retries - 1:
                    raise LLMException(f"LLM Provider internal error: {str(e)}")
                time.sleep(delay)
                delay *= 2

    @staticmethod
    def calculate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate USD cost based on standard model pricing per 1M tokens"""
        pricing = {
            "gpt-4o": {"input": 2.50 / 1_000_000, "output": 10.00 / 1_000_000},
            "gpt-4o-mini": {"input": 0.15 / 1_000_000, "output": 0.60 / 1_000_000},
            "gpt-4-turbo": {"input": 10.00 / 1_000_000, "output": 30.00 / 1_000_000},
            "gemini-1.5-flash": {"input": 0.075 / 1_000_000, "output": 0.30 / 1_000_000},
            "gemini-1.5-pro": {"input": 1.25 / 1_000_000, "output": 5.00 / 1_000_000},
            "gemini-2.0-flash": {"input": 0.10 / 1_000_000, "output": 0.40 / 1_000_000},
        }
        rates = pricing.get(model, {"input": 0.50 / 1_000_000, "output": 1.50 / 1_000_000})
        total_cost = (prompt_tokens * rates["input"]) + (completion_tokens * rates["output"])
        return round(total_cost, 6)

def _is_placeholder_key(key: Optional[str]) -> bool:
    if not key or not isinstance(key, str):
        return True
    cleaned = key.strip().lower()
    return cleaned == "" or "placeholder" in cleaned or "your-" in cleaned or cleaned in ("none", "null")

class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
        self.api_key = None if _is_placeholder_key(key) else key
        self.model = model or os.getenv("LLM_MODEL", "gpt-4o-mini")

    def generate(self, context: str, system_prompt: Optional[str] = None) -> LLMResponse:
        # Mock Fallback when API key is empty / None (preserves offline dev and unit tests)
        if not self.api_key:
            logger.info("OpenAI API key missing; falling back to offline mock response.")
            return LLMResponse(
                text='{"summary": "Potential security vulnerability detected in cloud configuration.", "observed": ["Public ingress allowed on restricted ports."], "inferred": ["Unrestricted exposure increases vulnerability to automated scanning."], "unknown": ["Business application running on this instance."], "recommendations": ["Restrict ingress to authorized IP CIDRs."], "confidence_score": 0.90}',
                tokens={"prompt": 50, "completion": 60, "total": 110},
                cost=0.000045,
                model=self.model,
                provider="openai"
            )

        def _execute():
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": context})

            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.2
            )

            text = response.choices[0].message.content or ""
            usage = response.usage
            prompt_tokens = usage.prompt_tokens if usage else 0
            completion_tokens = usage.completion_tokens if usage else 0
            total_tokens = usage.total_tokens if usage else (prompt_tokens + completion_tokens)
            cost = self.calculate_cost(self.model, prompt_tokens, completion_tokens)

            return LLMResponse(
                text=text,
                tokens={
                    "prompt": prompt_tokens,
                    "completion": completion_tokens,
                    "total": total_tokens
                },
                cost=cost,
                model=self.model,
                provider="openai"
            )

        return self.call_with_retry(_execute)

class GeminiProvider(LLMProvider):
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("LLM_API_KEY")
        self.api_key = None if _is_placeholder_key(key) else key
        self.model = model or os.getenv("LLM_MODEL", "gemini-1.5-flash")

    def generate(self, context: str, system_prompt: Optional[str] = None) -> LLMResponse:
        # Mock Fallback when API key is empty / None
        if not self.api_key:
            logger.info("Gemini API key missing; falling back to offline mock response.")
            return LLMResponse(
                text='{"summary": "Identified misconfiguration exposing critical resources.", "observed": ["Resource has no active MFA or encryption."], "inferred": ["Potential unauthorized credential usage."], "unknown": ["Active connection sessions."], "recommendations": ["Enable MFA and rotate keys."], "confidence_score": 0.88}',
                tokens={"prompt": 60, "completion": 50, "total": 110},
                cost=0.000019,
                model=self.model,
                provider="gemini"
            )

        def _execute():
            from google import genai
            client = genai.Client(api_key=self.api_key)
            
            # Combine system prompt with context if provided
            full_prompt = f"System Instructions:\n{system_prompt}\n\nUser Context:\n{context}" if system_prompt else context
            response = client.models.generate_content(
                model=self.model,
                contents=full_prompt
            )

            text = getattr(response, "text", "") or ""
            usage = getattr(response, "usage_metadata", None)
            prompt_tokens = getattr(usage, "prompt_token_count", 0) if usage else 0
            completion_tokens = getattr(usage, "candidates_token_count", 0) if usage else 0
            total_tokens = getattr(usage, "total_token_count", prompt_tokens + completion_tokens) if usage else 0
            cost = self.calculate_cost(self.model, prompt_tokens, completion_tokens)

            return LLMResponse(
                text=text,
                tokens={
                    "prompt": prompt_tokens,
                    "completion": completion_tokens,
                    "total": total_tokens
                },
                cost=cost,
                model=self.model,
                provider="gemini"
            )

        return self.call_with_retry(_execute)

class LocalProvider(LLMProvider):
    def __init__(self, model: Optional[str] = None):
        self.model = model or os.getenv("LLM_MODEL", "llama3")

    def generate(self, context: str, system_prompt: Optional[str] = None) -> LLMResponse:
        return LLMResponse(
            text='{"summary": "Local analysis complete", "observed": ["Local inspection"], "inferred": ["Potential local threat"], "unknown": ["Remote telemetry"], "recommendations": ["Check host integrity"], "confidence_score": 0.85}',
            tokens={"prompt": 40, "completion": 40, "total": 80},
            cost=0.0,
            model=self.model,
            provider="local"
        )

def get_llm_provider() -> LLMProvider:
    provider_name = os.getenv("LLM_PROVIDER", "local").lower()
    if provider_name == "openai":
        return OpenAIProvider()
    elif provider_name == "gemini":
        return GeminiProvider()
    else:
        return LocalProvider()
