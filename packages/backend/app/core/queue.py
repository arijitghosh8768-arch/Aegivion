import asyncio
from typing import Dict, Any, Callable
import uuid

# In-memory queue to simulate Redis/Celery for local dev
# This fulfills the Week 10 requirement to move scans off the request path
_task_queue = asyncio.Queue()
_task_status: Dict[str, str] = {}

async def enqueue_scan(account_id: str, scan_func: Callable) -> str:
    """
    Optimization: Enqueue a cloud scan and return immediately.
    The caller will receive a scan_id to poll status.
    """
    scan_id = str(uuid.uuid4())
    _task_status[scan_id] = "queued"
    await _task_queue.put((scan_id, account_id, scan_func))
    return scan_id

def get_scan_status(scan_id: str) -> str:
    return _task_status.get(scan_id, "unknown")

async def _worker_loop():
    """
    Optimization: Background worker that processes tasks off the main thread.
    """
    while True:
        scan_id, account_id, scan_func = await _task_queue.get()
        _task_status[scan_id] = "running"
        try:
            # Simulate the long-running scan
            await asyncio.to_thread(scan_func, account_id)
            _task_status[scan_id] = "completed"
        except Exception as e:
            _task_status[scan_id] = f"failed: {str(e)}"
        finally:
            _task_queue.task_done()

# Start the background worker (usually this would be called during app startup)
# asyncio.create_task(_worker_loop())
