"""Finding-accuracy regression: pre-optimization collectors vs current collectors.

Both sides run against the *same* deterministic ``FakeAWS`` fixtures, with the
same rule engine, so any difference in the produced findings is a behavioural
regression rather than fixture noise.

The "before" implementations live in ``tests/fixtures/legacy_collectors`` and are
byte-for-byte copies of the collector modules as they were before the
scan-optimization work; they are loaded from that path so future edits to
``app/cloud/aws/collectors`` cannot silently change the baseline.

What is compared (as the brief requires, counts alone are not enough):

* the full finding set: ``(rule_id, asset_id, severity, evidence)``
* per-rule finding counts
* collected asset ids and types
* checks executed (rules loaded x assets evaluated, plus API calls issued)
* failed / unavailable checks (collector ``collection_status`` and UNKNOWN values)
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, Iterable, List

import pytest

from tests.perf.fake_aws import FakeAWS

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIXTURE_DIR = os.path.join(BACKEND_DIR, "tests", "fixtures", "legacy_collectors")
REGION = "ap-south-1"

FIXTURE_SIZES = dict(
    buckets=14,
    iam_users=6,
    iam_roles=4,
    iam_groups=3,
    iam_policies=2,
    ec2_instances=8,
    security_groups=6,
    vpcs=3,
    subnets=6,
    rds_instances=2,
)

VOLATILE_KEYS = {
    "collected_at",
    "first_seen",
    "last_seen",
    "timestamp",
    "created_at_utc",
    "updated_at",
}


def _load_legacy(module_name: str, filename: str):
    path = os.path.join(FIXTURE_DIR, filename)
    spec = importlib.util.spec_from_file_location(f"legacy_collectors_{module_name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


LEGACY = {
    "s3": (_load_legacy("s3", "s3.py"), "S3Collector"),
    "iam": (_load_legacy("iam", "iam.py"), "IAMCollector"),
    "subnets": (_load_legacy("subnets", "subnets.py"), "SubnetCollector"),
    "vpc": (_load_legacy("vpc", "vpc.py"), "VPCCollector"),
}


# ------------------------------------------------------------------ normalization
def _normalize(value: Any) -> Any:
    """Drop volatile timestamps and ordering so two runs are comparable."""
    if isinstance(value, dict):
        return {
            k: _normalize(v)
            for k, v in sorted(value.items())
            if k not in VOLATILE_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, float):
        return round(value, 6)
    return value


def _fingerprint_findings(findings: Iterable[Dict[str, Any]]) -> List[str]:
    return sorted(
        json.dumps(
            {
                "rule_id": f.get("rule_id"),
                "asset_id": f.get("asset_id") or f.get("resource_id"),
                "severity": (f.get("severity") or "").lower(),
                "evidence": _normalize(f.get("evidence") or {}),
            },
            sort_keys=True,
            default=str,
        )
        for f in findings
    )


def _unknown_checks(assets: Iterable[Dict[str, Any]]) -> int:
    """Count checks AWS could not answer (value left as UNKNOWN)."""
    def _walk(value: Any) -> int:
        if isinstance(value, dict):
            return sum(_walk(v) for v in value.values())
        if isinstance(value, list):
            return sum(_walk(v) for v in value)
        return 1 if value == "UNKNOWN" else 0

    return sum(_walk(a.get("configuration") or {}) for a in assets)


def _collection_status(assets: Iterable[Dict[str, Any]]) -> Counter:
    return Counter((a.get("metadata") or {}).get("collection_status", "complete") for a in assets)


def _summarize(assets: List[Dict[str, Any]], executor, api_calls: int) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    applicable = 0
    for asset in assets:
        produced = executor.execute(asset)
        findings.extend(produced)
        if produced:
            applicable += 1
    return {
        "assets": sorted(a["asset_id"] for a in assets),
        "asset_types": Counter(a["type"] for a in assets),
        "rules_loaded": len(executor.rules),
        "assets_evaluated": len(assets),
        "checks_executed": len(executor.rules) * len(assets),
        "assets_with_findings": applicable,
        "findings": _fingerprint_findings(findings),
        "findings_by_rule": Counter(f.get("rule_id") for f in findings),
        "findings_by_severity": Counter((f.get("severity") or "").lower() for f in findings),
        "collection_status": _collection_status(assets),
        "unavailable_checks": _unknown_checks(assets),
        "api_calls": api_calls,
    }


async def _collect_all(collectors: Dict[str, Any], fake: FakeAWS) -> List[Dict[str, Any]]:
    assets: List[Dict[str, Any]] = []
    for collector in collectors.values():
        assets.extend(await collector.collect())
    return assets


@pytest.mark.asyncio
async def test_findings_match_pre_optimization_collectors():
    from app.cloud.aws.collectors.s3 import S3Collector
    from app.cloud.aws.collectors.iam import IAMCollector
    from app.cloud.aws.collectors.subnets import SubnetCollector
    from app.cloud.aws.collectors.vpc import VPCCollector
    from app.cloud.aws.scan.orchestrator import ScanOrchestrator
    from security.pipeline.detection_pipeline import DetectionPipeline

    fake = FakeAWS(**FIXTURE_SIZES)

    # --- before: pre-optimization collector implementations -------------------
    fake.reset_counters()
    legacy_collectors = {
        name: getattr(module, class_name)(fake, REGION)
        for name, (module, class_name) in LEGACY.items()
    }
    legacy_assets = await _collect_all(legacy_collectors, fake)
    legacy_api_calls = fake.total_calls

    # --- after: current collector implementations ----------------------------
    fake.reset_counters()
    orchestrator = ScanOrchestrator(cloud_account_id="00000000-0000-0000-0000-000000000000",
                                    organization_id="00000000-0000-0000-0000-000000000000")
    try:
        current_collectors = orchestrator._initialize_collectors(fake)
        current_collectors = {k: v for k, v in current_collectors.items() if k in LEGACY}
        current_collectors["s3"] = S3Collector(fake, REGION)
        current_collectors["iam"] = IAMCollector(fake, REGION)
        current_collectors["subnets"] = SubnetCollector(fake, REGION)
        current_collectors["vpc"] = VPCCollector(fake, REGION)
        current_assets = await _collect_all(current_collectors, fake)
        current_api_calls = fake.total_calls
    finally:
        orchestrator.db.close()

    # Same rule engine, no DB needed for rule evaluation.
    pipeline = DetectionPipeline(db=object())
    executor = pipeline.rule_executor
    from security.engine.executor import RuleExecutor

    rules = pipeline._load_rules()
    before = _summarize(legacy_assets, RuleExecutor(rules), legacy_api_calls)
    after = _summarize(current_assets, RuleExecutor(rules), current_api_calls)

    # Sanity: the fixtures actually exercised the pipeline.
    assert before["assets"], "no assets collected"
    assert before["findings"], "no findings produced"

    # Full finding-level comparison.
    assert after["findings"] == before["findings"]
    assert after["findings_by_rule"] == before["findings_by_rule"]
    assert after["findings_by_severity"] == before["findings_by_severity"]
    assert after["assets"] == before["assets"]
    assert after["asset_types"] == before["asset_types"]

    # Checks executed / failed / unavailable.
    assert after["rules_loaded"] == before["rules_loaded"]
    assert after["assets_evaluated"] == before["assets_evaluated"]
    assert after["checks_executed"] == before["checks_executed"]
    assert after["assets_with_findings"] == before["assets_with_findings"]
    assert after["collection_status"] == before["collection_status"]
    assert after["unavailable_checks"] == before["unavailable_checks"]
    assert after["api_calls"] == before["api_calls"]
