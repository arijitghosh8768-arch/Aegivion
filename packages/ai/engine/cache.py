import hashlib
import json
from typing import Optional, Dict, Any

class AICache:
    """
    Optimization: Aggressively caches LLM responses to avoid redundant calls.
    The cache key is a hash of the finding's evidence and the current prompt template version.
    """
    def __init__(self, prompt_version: str = "v1"):
        self.prompt_version = prompt_version
        self._cache: Dict[str, Any] = {}
        
    def _generate_key(self, evidence: Dict[str, Any]) -> str:
        # Sort keys to ensure deterministic hashing
        serialized_evidence = json.dumps(evidence, sort_keys=True)
        raw_key = f"{self.prompt_version}:{serialized_evidence}"
        return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()

    def get(self, evidence: Dict[str, Any]) -> Optional[Any]:
        key = self._generate_key(evidence)
        return self._cache.get(key)
        
    def set(self, evidence: Dict[str, Any], response: Any) -> None:
        key = self._generate_key(evidence)
        self._cache[key] = response

# Global instance for the AI engine
ai_cache = AICache(prompt_version="v2.1")
