"""Bounded concurrency helpers for AWS API calls.

AWS calls are I/O bound and the collectors used to issue them serially, which
dominated scan duration.  These helpers parallelise them while keeping the
total number of in-flight AWS requests bounded so we do not trip throttling.
"""

from __future__ import annotations

import asyncio
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable, List, Sequence, TypeVar

MAX_AWS_CONCURRENCY = int(os.getenv("AEGIVION_AWS_MAX_CONCURRENCY", "24"))
_PER_SERVICE_LIMIT = int(os.getenv("AEGIVION_PER_SERVICE_CONCURRENCY", "8"))

_slots = threading.BoundedSemaphore(MAX_AWS_CONCURRENCY)

_T = TypeVar("_T")


def _acquire_and_call(fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    with _slots:
        return fn(*args, **kwargs)


async def run_aws_call(fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """Run a blocking AWS call in a worker thread, respecting the global slot cap."""
    return await asyncio.to_thread(_acquire_and_call, fn, *args, **kwargs)


async def gather_aws(coros: Sequence[Any], per_service_limit: int = _PER_SERVICE_LIMIT) -> List[Any]:
    """gather with a per-service concurrency cap; preserves order."""
    sem = asyncio.Semaphore(per_service_limit)

    async def _guarded(coro):
        async with sem:
            return await coro

    return await asyncio.gather(*(_guarded(c) for c in coros), return_exceptions=True)


def parallel_map(fn: Callable[[_T], Any], items: Iterable[_T], max_workers: int = _PER_SERVICE_LIMIT) -> List[Any]:
    """Bounded parallel map for synchronous (legacy) discovery code."""
    materialised = list(items)

    def _worker(item: _T):
        return _acquire_and_call(fn, item)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(_worker, materialised))


# Process-wide cache for STS account id keyed by session id (boto3 sessions are
# not thread safe, but a single identity per session never changes).
_sts_cache: dict[int, str] = {}
_sts_lock = threading.Lock()


def get_account_id(session_or_client) -> str:
    """Return the AWS account id, cached per session/client.

    Pass an already-created STS client where possible: creating clients is a
    boto3 *session* mutation and must stay on the calling thread. This is a
    blocking call: always invoke it through ``run_aws_call``.
    """
    key = id(session_or_client)
    with _sts_lock:
        cached = _sts_cache.get(key)
    if cached is not None:
        return cached
    sts = session_or_client
    if not hasattr(sts, "get_caller_identity"):
        sts = sts.client("sts")
    # Callers already run this inside ``run_aws_call`` (which holds a global
    # slot). Acquiring a second slot here would deadlock once the pool is
    # saturated, so the wrapped call is issued directly.
    response = sts.get_caller_identity()
    account_id = response["Account"]
    with _sts_lock:
        _sts_cache[key] = account_id
    return account_id


def reset_sts_cache() -> None:
    with _sts_lock:
        _sts_cache.clear()
