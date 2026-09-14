import json
from typing import Dict, Any

class AIValidationError(Exception):
    pass

def validate_llm_json(raw_output: str, required_keys: list = None) -> Dict[str, Any]:
    """
    Hardening: Catch and parse malformed LLM JSON outputs.
    Ensures the system does not crash if the LLM hallucinates keys or truncates output.
    """
    if required_keys is None:
        required_keys = ["explanation", "severity"]
        
    try:
        # Step 1: Attempt to parse raw JSON
        # Some LLMs wrap JSON in markdown block ```json ... ```
        cleaned = raw_output.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
            
        parsed = json.loads(cleaned.strip())
        
    except json.JSONDecodeError as e:
        # We could attempt basic repair here (e.g. adding missing trailing brace),
        # but for security responses, it is safer to reject and let the upstream handler retry.
        raise AIValidationError(f"Failed to parse LLM output as JSON: {e}")
        
    # Step 2: Validate Schema
    missing_keys = [k for k in required_keys if k not in parsed]
    if missing_keys:
        raise AIValidationError(f"LLM output missing required keys: {missing_keys}")
        
    return parsed
