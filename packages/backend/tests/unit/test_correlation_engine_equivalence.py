"""Semantic equivalence for the indexed correlation engine.

The correlation engine used to rescan every asset relationship for every pair
of findings.  It now uses a prebuilt relationship index.  These tests pin the
optimised implementation to the original brute-force algorithm on the same
inputs so the speedup cannot silently change incident semantics.
"""

from __future__ import annotations

import hashlib

import pytest

from security.correlation.engine_v2 import CorrelationEngineV2, CorrelatedGroup


# ---------------------------------------------------------------------------
# Reference implementation: the original, unindexed algorithm.
# ---------------------------------------------------------------------------

def _reference_features(findings, assets):
    features = {}
    for f in findings:
        fid = f.get("finding_id", f.get("id"))
        asset_id = f.get("asset_id", f.get("resource_id"))
        vpc_id = None
        subnet_id = None
        asset_obj = next((a for a in assets if a.get("asset_id") == asset_id), None)
        if asset_obj and "configuration" in asset_obj:
            config = asset_obj["configuration"]
            vpc_id = config.get("vpc_id") or config.get("VpcId")
            subnet_id = config.get("subnet_id") or config.get("SubnetId")
        features[fid] = {
            "finding_id": fid,
            "asset_id": asset_id,
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "severity": f.get("severity", "medium").lower(),
            "rule_id": f.get("rule_id"),
            "detected_at": f.get("created_at") or "2026-01-01T00:00:00",
        }
    return features


def _reference_pairs(features, relationships):
    pairs = []
    fids = list(features.keys())
    for i in range(len(fids)):
        for j in range(i + 1, len(fids)):
            fid1, fid2 = fids[i], fids[j]
            feat1, feat2 = features[fid1], features[fid2]
            correlate = False
            if feat1["asset_id"] == feat2["asset_id"] and feat1["asset_id"] is not None:
                correlate = True
            a1, a2 = feat1["asset_id"], feat2["asset_id"]
            if a1 and a2 and a1 != a2:
                for rel in relationships:
                    src = rel.get("source_asset_id", rel.get("source_id"))
                    tgt = rel.get("target_asset_id", rel.get("target_id"))
                    if (src == a1 and tgt == a2) or (src == a2 and tgt == a1):
                        correlate = True
            if feat1["vpc_id"] and feat2["vpc_id"] and feat1["vpc_id"] == feat2["vpc_id"]:
                correlate = True
            if correlate:
                pairs.append((fid1, fid2))
    return pairs


def _reference_groups(findings, assets, relationships):
    features = _reference_features(findings, assets)
    pairs = _reference_pairs(features, relationships)

    adj = {}
    for u, v in pairs:
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)

    visited, clusters = set(), []
    for node in adj:
        if node in visited:
            continue
        cluster, queue = [], [node]
        visited.add(node)
        while queue:
            curr = queue.pop(0)
            cluster.append(curr)
            for neighbor in adj[curr]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        clusters.append(cluster)

    groups = []
    for cluster in clusters:
        group_id = f"CG-{hashlib.sha256(''.join(sorted(cluster)).encode()).hexdigest()[:8].upper()}"
        asset_ids = list({features[fid]["asset_id"] for fid in cluster if features[fid]["asset_id"]})
        reasons, strength = [], "weak"
        if len(asset_ids) == 1:
            reasons.append("shared_asset")
            strength = "moderate"

        has_confirmed_rel, has_vpc_context = False, False
        for fid1 in cluster:
            for fid2 in cluster:
                if fid1 == fid2:
                    continue
                a1, a2 = features[fid1]["asset_id"], features[fid2]["asset_id"]
                if a1 and a2 and a1 != a2:
                    for rel in relationships:
                        src = rel.get("source_asset_id", rel.get("source_id"))
                        tgt = rel.get("target_asset_id", rel.get("target_id"))
                        rel_type = rel.get("relationship_type", rel.get("type"))
                        if (src == a1 and tgt == a2) or (src == a2 and tgt == a1):
                            has_confirmed_rel = True
                            reasons.append(f"confirmed_asset_relationship: {rel_type}")
                    v1, v2 = features[fid1].get("vpc_id"), features[fid2].get("vpc_id")
                    if v1 and v2 and v1 == v2:
                        has_vpc_context = True
                        reasons.append("shared_vpc")

        reasons = list(set(reasons))
        if has_confirmed_rel:
            strength = "strong"
        elif has_vpc_context and len(asset_ids) > 1:
            strength = "moderate"

        is_candidate = strength == "strong" or any(
            features[fid]["severity"] in ["critical", "high"] for fid in cluster
        )
        groups.append((group_id, sorted(cluster), sorted(asset_ids), sorted(reasons), strength, is_candidate))
    return sorted(groups)


def _fixtures():
    findings, assets, relationships = [], [], []
    sevs = ["critical", "high", "medium", "low"]
    for idx in range(36):
        asset_id = f"aws:ec2:i-{idx % 12:03d}"
        findings.append({
            "id": f"f-{idx:03d}",
            "finding_id": f"f-{idx:03d}",
            "asset_id": asset_id,
            "severity": sevs[idx % 4],
            "rule_id": f"RULE_{idx % 7}",
        })
        if idx % 9 == 0:
            findings[-1]["asset_id"] = None

    for idx in range(12):
        assets.append({
            "asset_id": f"aws:ec2:i-{idx:03d}",
            "configuration": {"vpc_id": f"vpc-{idx % 3}", "subnet_id": f"subnet-{idx % 5}"},
        })
    # An asset id that repeats: the reference scan must resolve the first one.
    assets.append({"asset_id": "aws:ec2:i-000", "configuration": {"vpc_id": "vpc-other"}})

    for idx in range(12):
        for target in {(idx + 1) % 12, (idx + 2) % 12, idx}:
            relationships.append({
                "source_asset_id": f"aws:ec2:i-{idx:03d}",
                "target_asset_id": f"aws:ec2:i-{target:03d}",
                "relationship_type": "CONNECTED_TO" if target % 2 else "CAN_ACCESS",
                "confidence": 0.9,
            })
    # Duplicate, unknown-shape and string-only relationship records.
    relationships.append({
        "source_asset_id": "aws:ec2:i-001",
        "target_asset_id": "aws:ec2:i-005",
        "relationship_type": "CAN_ACCESS",
    })
    relationships.append({"source_asset_id": None, "target_asset_id": "aws:ec2:i-002", "relationship_type": "X"})
    return findings, assets, relationships


@pytest.mark.parametrize(
    "findings, assets, relationships",
    [
        _fixtures(),
        ([], [], []),
        (
            [{"finding_id": "a", "asset_id": "x", "severity": "high"}],
            [{"asset_id": "x", "configuration": {}}],
            [],
        ),
    ],
)
def test_indexed_correlation_matches_bruteforce(findings, assets, relationships):
    engine = CorrelationEngineV2()
    engine.load_data(findings=findings, assets=assets, relationships=relationships)
    groups = engine.correlate()

    actual = sorted(
        (
            g.group_id,
            sorted(g.finding_ids),
            sorted(g.asset_ids),
            sorted(g.reasons),
            getattr(g.strength, "value", g.strength),
            bool(g.incident_candidate),
        )
        for g in groups
    )
    assert actual == _reference_groups(findings, assets, relationships)


def test_repeated_correlation_is_stable():
    findings, assets, relationships = _fixtures()
    outputs = []
    for _ in range(3):
        engine = CorrelationEngineV2()
        engine.load_data(findings=findings, assets=assets, relationships=relationships)
        outputs.append([
            (g.group_id, g.finding_ids, sorted(g.asset_ids), sorted(g.reasons), g.strength, g.incident_candidate)
            for g in engine.correlate()
        ])
    assert outputs[0] == outputs[1] == outputs[2]
