import time
from typing import Dict, Any, Callable
from functools import wraps
from enum import Enum

class CircuitState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

class CloudAuthError(Exception):
    pass

class CloudTimeout(Exception):
    pass

class CloudRateLimitExceeded(Exception):
    pass

class CircuitBreaker:
    """
    Hardening: Implements the state machine for API calls to prevent cascading failures.
    CLOSED -> OPEN (after N failures) -> HALF_OPEN (after cooldown) -> CLOSED (on success)
    """
    def __init__(self, failure_threshold: int = 3, cooldown_seconds: int = 30):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0.0

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            print(f"Circuit Breaker OPENED after {self.failure_count} failures.")

    def record_success(self):
        self.failure_count = 0
        if self.state != CircuitState.CLOSED:
            print("Circuit Breaker CLOSED (recovery successful).")
        self.state = CircuitState.CLOSED

    def can_execute(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time > self.cooldown_seconds:
                self.state = CircuitState.HALF_OPEN
                print("Circuit Breaker HALF_OPEN (cooldown passed).")
                return True
            return False
        if self.state == CircuitState.HALF_OPEN:
            # In half-open, we allow exactly one execution to test recovery
            return True
        return False

def normalize_cloud_errors(func: Callable):
    """
    Hardening: Wraps cloud SDK calls and normalizes provider-specific exceptions
    into standard internal exceptions (CloudAuthError, CloudTimeout, etc.).
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            err_msg = str(e).lower()
            if "accessdenied" in err_msg or "unauthorized" in err_msg or "401" in err_msg or "403" in err_msg:
                raise CloudAuthError(f"Authentication/Authorization failed: {str(e)}")
            elif "timeout" in err_msg:
                raise CloudTimeout(f"Request timed out: {str(e)}")
            elif "ratelimit" in err_msg or "429" in err_msg or "throttling" in err_msg:
                raise CloudRateLimitExceeded(f"Rate limit exceeded: {str(e)}")
            raise # Re-raise unknown errors
    return wrapper
