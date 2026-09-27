from typing import Dict, Any
from app.models.security_event import SecurityEvent

class BaseNormalizer:
    @staticmethod
    def normalize(raw_event: Dict[str, Any], context: Dict[str, Any]) -> SecurityEvent:
        raise NotImplementedError
