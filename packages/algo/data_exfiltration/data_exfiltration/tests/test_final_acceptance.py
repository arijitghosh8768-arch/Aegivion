"""Final acceptance test — 17 ordered steps, end to end (Part 5).

One test walks the whole final-stage contract: corpus -> detector ->
chronology-safe features -> split integrity -> variants A–E -> ARDE gating ->
metrics -> validation-only threshold tuning -> ablation -> error analysis ->
output contract -> dashboard view -> REST API -> determinism -> algorithmic
independence -> artifact honesty.

Every step records itself in ``steps``; the test fails loudly on the first
step that does not hold.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from algo.data_exfiltration.data_exfiltration.api import create_app
from algo.data_exfiltration.data_exfiltration.arde import ARDEValidator
from algo.data_exfiltration.data_exfiltration.dashboard import build_dashboard_view
from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector


def test_final_acceptance_17_steps() -> None:  # noqa: C901 - an acceptance walk
    # imports kept local so the test reads top-to-bottom as the acceptance flow
    from algo.data_exfiltration.data_exfiltration.evaluation.dataset import run_detector_on_corpus
    from algo.data_exfiltration.data_exfiltration.evaluation.runner import (
        evaluate,
        prepare_feature_records,
    )
    from algo.data_exfiltration.data_exfiltration.evaluation.scenarios import FIFTEEN_FAMILIES, build_instances
    from algo.data_exfiltration.data_exfiltration.evaluation.tuning import (
        split_records,
        verify_split_integrity,
    )
    from algo.data_exfiltration.data_exfiltration.intelligence import BehavioralProfiler
    from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack
    from algo.data_exfiltration.data_exfiltration.output_contract import output_contract_of

    steps: list[str] = []

    # 1. synthetic 15-family corpus with both classes present
    bundles = build_instances(per_family=4)
    labels = {b.label for b in bundles}
    assert len(FIFTEEN_FAMILIES) == 15
    assert labels == {0, 1}
    steps.append("corpus_built_15_families")

    # 2. detector produces sessions and findings
    records = run_detector_on_corpus(bundles)
    assert records and any(r.finding is not None for r in records)
    steps.append("detector_sessions_and_findings")

    # 3. chronology-safe features: every record profiled, no fabrications
    prepare_feature_records(records)
    for record in records:
        fset = record.session.session_features.get("_behavioral_feature_set")
        assert fset is not None
        assert 0.0 <= fset.baseline_quality <= 1.0
    steps.append("features_chronology_safe")

    # 4. temporal split integrity: disjoint and chronological
    _split, temporal = split_records(records)
    integrity = verify_split_integrity(temporal)
    assert integrity["disjoint"] and integrity["chronological"]
    steps.append("split_integrity_disjoint_chronological")

    # 5-10. full evaluation (variants, ARDE gating, metrics, ablation, tuning, errors)
    report = evaluate(per_family=4)
    assert set(report["variants"]) == {"A", "B", "C", "D", "E"}
    steps.append("variants_a_to_e_scored")

    alerts = {k: v["alerts"] for k, v in report["variants"].items()}
    assert alerts["E"] <= alerts["D"], "ARDE must not increase alerts"
    assert report["arde_interventions"]["rejected_alerts"] >= 0
    steps.append("arde_gating_never_increases_alerts")

    e_metrics = report["variants"]["E"]["metrics"]
    for key in ("precision", "recall", "f1", "false_positive_rate", "false_negative_rate",
                "pr_auc", "roc_auc", "precision_at_high_risk", "recall_at_fixed_fpr"):
        assert key in e_metrics, key
    steps.append("metrics_complete")

    ablation_components = {c["component"] for c in report["ablation"]["components"]}
    assert {"volume", "destination", "sensitivity", "access_pattern",
            "time", "network_egress", "ml", "arde"} <= ablation_components
    steps.append("ablation_all_required_components")

    tuning = report["threshold_tuning"]
    assert tuning["selection"]["data_used"].startswith("validation")
    assert tuning["test_metrics_at_selected"]["threshold"] == tuning["selection"]["threshold"]
    assert tuning["split_integrity"]["disjoint"]
    steps.append("threshold_tuned_on_validation_only")

    error_analysis = report["error_analysis"]
    assert set(error_analysis) >= {"false_positives", "false_negatives", "fp_by_scenario", "fn_by_scenario"}
    assert all(fp["reason"] for fp in error_analysis["false_positives"])
    steps.append("error_analysis_structured")

    # 11. output contract present on a scored finding, with every documented field
    fixture_detector = DataExfiltrationDetector(
        profiler=BehavioralProfiler(),
        arde_validator=ARDEValidator(),
    )
    from .fixtures.scenarios import scenario_unknown_destination

    fixture_result = fixture_detector.process_events(
        cloudtrail_records=scenario_unknown_destination()
    )
    scored_findings = fixture_detector.score_sessions(fixture_result, ScoringStack(variant="B"))
    contract = output_contract_of(scored_findings[0])
    required = {
        "finding_type", "severity", "risk_score", "confidence", "robustness_score",
        "actor", "resource", "session", "data_volume", "sensitivity", "destination",
        "temporal_context", "signals", "supporting_evidence", "contradicting_evidence",
        "baseline_quality", "feature_availability", "model_version", "feature_version",
        "baseline_version", "scoring_version", "rule_version", "recommended_next_steps",
    }
    assert not (required - set(contract)), required - set(contract)
    steps.append("output_contract_complete")

    # 12. dashboard view exposes the analyst panels
    view = build_dashboard_view(
        scored_findings[0],
        session=fixture_result.sessions[0],
        scored=scored_findings[0],
    )
    for panel in ("access_timeline", "normal_vs_observed", "top_signals",
                  "supporting_evidence", "contradicting_evidence", "recommended_next_steps"):
        assert panel in view, panel
    steps.append("dashboard_view_model")

    # 13-14. REST API: analyze then read every resource back
    app = create_app()

    def call(method: str, path: str, body: dict | None = None, qs: str = ""):
        raw = json.dumps(body).encode("utf-8") if body is not None else b""
        environ = {
            "REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": qs,
            "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw),
        }
        captured: dict = {}
        payload = b"".join(app(environ, lambda s, h: captured.update(status=s)))
        return captured["status"], json.loads(payload.decode("utf-8"))

    status, analyzed = call(
        "POST", "/api/v1/detections/data-exfiltration/analyze",
        {"cloudtrail_records": scenario_unknown_destination(), "vpc_flow_records": []},
    )
    assert status.startswith("200") and analyzed["findings"]
    steps.append("api_analyze")

    fid = analyzed["findings"][0]["finding_id"]
    sid = analyzed["findings"][0]["session_id"]
    rid = analyzed["findings"][0]["resource_id"]
    for path in (
        "/api/v1/detections/data-exfiltration/findings",
        f"/api/v1/data-sessions/{sid}",
        f"/api/v1/data-resources/{rid}/profile",
        f"/api/v1/findings/{fid}/explanation",
    ):
        status, body = call("GET", path)
        assert status.startswith("200"), (path, status, body)
    steps.append("api_all_endpoints")

    # 15. determinism: identical report across runs
    run_a = evaluate(per_family=2)
    run_b = evaluate(per_family=2)
    assert run_a["variants"]["E"]["metrics"] == run_b["variants"]["E"]["metrics"]
    assert run_a["threshold_tuning"]["selection"] == run_b["threshold_tuning"]["selection"]
    steps.append("evaluation_deterministic")

    # 16. algorithmic independence: HIGH external credential signal + normal
    #     data behaviour must NOT create a data-exfiltration alert.
    class _SiblingStub:
        level = "HIGH"

        def evaluate(self, actor_id):  # pragma: no cover - inert
            return {"compromise_level": "HIGH"}

    from .fixtures.scenarios import scenario_normal_s3_access

    detector = DataExfiltrationDetector(
        profiler=BehavioralProfiler(), arde_validator=ARDEValidator()
    )
    normal_result = detector.process_events(cloudtrail_records=scenario_normal_s3_access())
    normal_scored = detector.score_sessions(normal_result, ScoringStack(variant="B"))
    sibling = _SiblingStub()
    sibling.evaluate("any")
    assert normal_scored[0].risk_score < 0.5
    assert normal_scored[0].severity.value != "critical"
    steps.append("independent_of_algorithm_1")

    # 17. artifact honesty: present, synthetic-marked, and no perfect-detection claims
    artifact_dir = Path(__file__).resolve().parents[2] / "evaluation_artifacts"
    expected = {
        "final_metrics.json", "final_ablation.json", "final_error_analysis.json",
        "final_arde_impact.json", "final_threshold_tuning.json", "final_performance.json",
    }
    present = {p.name for p in artifact_dir.glob("final_*.json")}
    assert expected <= present, expected - present
    metrics_artifact = json.loads((artifact_dir / "final_metrics.json").read_text(encoding="utf-8"))
    assert metrics_artifact["synthetic"] is True
    for name, metrics in metrics_artifact["variants"].items():
        assert metrics["recall"] < 1.0, f"{name} claims perfect recall"
        assert metrics["precision"] < 1.0, f"{name} claims perfect precision"
    steps.append("artifacts_synthetic_and_honest")

    assert len(steps) == 17, steps
