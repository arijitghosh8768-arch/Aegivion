import logging
import json
from datetime import datetime
from typing import Any, Dict
from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar("request_id", default="")

class StructuredLogger:
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.logger = logging.getLogger(service_name)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
            
    def log(self, level: str, message: str, **kwargs: Any) -> None:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "service": self.service_name,
            "level": level,
            "message": message,
            "request_id": request_id_var.get(),
            **kwargs
        }
        print(json.dumps(log_entry))
        
    def info(self, message: str, **kwargs: Any) -> None:
        self.log("INFO", message, **kwargs)
        
    def error(self, message: str, **kwargs: Any) -> None:
        self.log("ERROR", message, **kwargs)
        
    def debug(self, message: str, **kwargs: Any) -> None:
        self.log("DEBUG", message, **kwargs)

logger = StructuredLogger("backend")
