"""Concurrency behaviour of the AWS collectors and the orchestrator.

These tests pin the properties the optimization relies on: collectors overlap,
a failing collector does not take the scan down, in-flight AWS calls stay
bounded, and concurrent collection preserves deterministic asset ordering.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time

import pytest

from app.cloud.aws import concurrency
from app.cloud.aws.scan.orchestrator import ScanOrchestrator


class _Collector:
    def __init__(self, assets=None, delay=0.0, error=None):
        self._assets = assets or []
        self._delay = delay
        self._error = error
        self.calls = 0

    async def collect(self):
        self.calls += 1
        await asyncio.sleep(self._delay)
        if self._error:
            raise self._error
        return self._assets


@pytest.mark.asyncio
async def test_run_collectors_overlaps_and_keeps_registry_order():
    slow_a = _Collector([{"asset_id": "a"}], delay=0.2)
    slow_b = _Collector([{"asset_id": "b"}], delay=0.2)
    slow_c = _Collector([{"asset_id": "c"}], delay=0.2)

    started = time.perf_counter()
    results = await ScanOrchestrator("x", "y")._run_collectors(
        {"a": slow_a, "b": slow_b, "c": slow_c}
    )
    elapsed = time.perf_counter() - started

    # Serial execution would take 0.6s; overlapping should be near 0.2s.
    assert elapsed < 0.45
    assert [r["assets"][0]["asset_id"] for r in results.values()] == ["a", "b", "c"]
    assert all(r["success"] for r in results.values())


@pytest.mark.asyncio
async def test_failing_collector_is_contained():
    ok = _Collector([{"asset_id": "ok"}])
    bad = _Collector(error=RuntimeError("AccessDenied"))

    results = await ScanOrchestrator("x", "y")._run_collectors({"ok": ok, "bad": bad})

    assert results["ok"] == {"success": True, "assets": [{"asset_id": "ok"}], "count": 1}
    assert results["bad"]["success"] is False
    assert "AccessDenied" in results["bad"]["error"]
    assert results["bad"]["assets"] == []


@pytest.mark.asyncio
async def test_global_aws_concurrency_is_bounded(monkeypatch):
    limit = 4
    original = concurrency._slots
    monkeypatch.setattr(concurrency, "_slots", threading.BoundedSemaphore(limit))
    monkeypatch.setattr(concurrency, "MAX_AWS_CONCURRENCY", limit)

    active = 0
    peak = 0
    lock = threading.Lock()

    def _call(delay):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delay)
            return "ok"
        finally:
            with lock:
                active -= 1

    try:
        results = await asyncio.gather(
            *(concurrency.run_aws_call(_call, 0.01) for _ in range(40))
        )
    finally:
        monkeypatch.setattr(concurrency, "_slots", original)

    assert results == ["ok"] * 40
    assert peak <= limit, f"peak in-flight AWS calls {peak} exceeded cap {limit}"


@pytest.mark.asyncio
async def test_gather_aws_limits_per_service_and_preserves_order():
    active = 0
    peak = 0

    async def _task(value):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return value

    results = await concurrency.gather_aws(
        [_task(i) for i in range(20)], per_service_limit=3
    )
    assert results == list(range(20))
    assert peak <= 3


@pytest.mark.asyncio
async def test_s3_concurrent_collection_preserves_listing_order():
    from tests.perf.fake_aws import FakeAWS
    from app.cloud.aws.collectors.s3 import S3Collector

    fake = FakeAWS(latency=0.0, buckets=25)
    collector = S3Collector(fake, region="ap-south-1")
    assets = await collector.collect()

    expected = [f"bench-bucket-{i:03d}" for i in range(25)]
    assert [a["name"] for a in assets] == expected
    # Every call made by the serial implementation is still made.
    assert fake.calls.get("s3:ListBuckets") == 1
    # All seven per-bucket controls are still collected for every bucket.
    assert fake.calls.get("s3:GetBucketPolicy") == 25
