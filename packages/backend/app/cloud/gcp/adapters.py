import time
import random
from typing import Dict, Any, Callable
from functools import wraps

def with_retry(max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 10.0):
    """
    Exponential backoff with jitter for cloud API calls.
    Hardening: Protects against transient API rate limits and network flakes.
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        raise RuntimeError(f"Action failed after {max_attempts} attempts: {str(e)}")
                    # Exponential backoff with jitter
                    delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
                    jitter = random.uniform(0, 0.1 * delay)
                    time.sleep(delay + jitter)
                    print(f"Retrying {func.__name__} in {delay+jitter:.2f}s... (Attempt {attempt}/{max_attempts})")
        return wrapper
    return decorator

@with_retry(max_attempts=3)
def disable_gcp_service_account_key(key_id: str, dry_run: bool = True) -> Dict[str, Any]:
    """
    Mock adapter to disable a GCP user-managed service account key.
    Enforces the safety-first dry_run pattern.
    """
    # Simulated API failure for testing
    if not dry_run and random.random() < 0.2:
        raise ConnectionError("Simulated GCP API rate limit exceeded")
        
    preview = {
        "action": "DISABLE_SERVICE_ACCOUNT_KEY",
        "target": key_id,
        "changes": [
            f"Set status of key {key_id} to DISABLED"
        ]
    }
    
    if dry_run:
        return {"status": "dry_run", "preview": preview}
        
    return {"status": "executed", "details": preview, "verification": "Pending"}

@with_retry(max_attempts=3)
def remove_gcp_public_ip(instance_id: str, dry_run: bool = True) -> Dict[str, Any]:
    """
    Mock adapter to remove a public IP from a GCP compute instance.
    Enforces the safety-first dry_run pattern.
    """
    # Simulated API failure for testing
    if not dry_run and random.random() < 0.2:
        raise ConnectionError("Simulated GCP API timeout")
        
    preview = {
        "action": "REMOVE_PUBLIC_IP",
        "target": instance_id,
        "changes": [
            f"Remove accessConfigs block from networkInterfaces for instance {instance_id}"
        ]
    }
    
    if dry_run:
        return {"status": "dry_run", "preview": preview}
        
    return {"status": "executed", "details": preview, "verification": "Pending"}

