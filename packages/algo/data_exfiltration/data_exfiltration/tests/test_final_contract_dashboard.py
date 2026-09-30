"""Output contract + dashboard view-model tests (Part 5)."""

from __future__ import annotations

import json

from algo.data_exfiltration.data_exfiltration.arde import ARDEValidator
from algo.data_exfiltration.data_exfiltration.dashboard import build_dashboard_view
from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector
from algo.data_exfiltration.data_exfiltration.intelligence import BehavioralProfiler
from algo.data_exfiltration.data_exfiltration.ml.pipeline import ScoringStack
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.output_contract import (
    OUTPUT_CONTRACT_VERSION,
    output_contract_of,
)

from .fixtures.scenarios import scenario_abnormal_enumeration, scenario_normal_s3_access

#: The documented fields every released finding must expose.
REQUIRED_CONTRACT_FIELDS = {
    "finding_type",
    "severity",
    "risk_score",
    "confidence",
    "robustness_score",
    "actor",
    "resource",
    "session",
    "data_volume",
    "sensitivity",
    "destination",
    "temporal_context",
    "signals",
    "supporting_evidence",
    "contradicting_evidence",
    "baseline_quality",
    "feature_availability",
    "model_version",
    "feature_version",
    "baseline_version",
    "scoring_version",
    "rule_version",
    "recommended_next_steps",
}


def _scored_finding(records):
    detector = DataExfiltrationDetector(
        profiler=BehavioralProfiler(),
        arde_validator=ARDEValidator(),
    )
    result = detector.process_events(cloudtrail_records=records)
    scored = detector.score_sessions(result, ScoringStack(variant="B"))
    return result, scored[0]


class TestOutputContract:
    def test_all_documented_fields_present(self) -> None:
        _result, finding = _scored_finding(scenario_unknown_destination_records())
        contract = output_contract_of(finding)
        assert contract is not None
        assert contract["contract_version"] == OUTPUT_CONTRACT_VERSION
        missing = REQUIRED_CONTRACT_FIELDS - set(contract)
        assert not missing, missing
        assert contract["finding_type"] == "data_discovery"
        assert contract["rule_version"].startswith("data-exfil-rules-")
        assert contract["recommended_next_steps"], "next steps must never be empty"

    def test_contract_is_json_serializable(self) -> None:
        _result, finding = _scored_finding(scenario_unknown_destination_records())
        payload = json.dumps(output_contract_of(finding), sort_keys=True)
        assert "output_contract" not in payload  # no self-reference

    def test_discovery_only_finding_still_has_contract(self) -> None:
        detector = DataExfiltrationDetector()  # Part 1 path: no profiler, no ARDE
        result = detector.process_events(cloudtrail_records=scenario_normal_s3_access())
        contract = output_contract_of(result.findings[0])
        assert contract is not None
        assert contract["risk_score"] is None
        assert contract["model_version"]  # default identity, honestly labelled

    def test_evidence_panels_always_both_present(self) -> None:
        _result, finding = _scored_finding(scenario_unknown_destination_records())
        contract = output_contract_of(finding)
        assert isinstance(contract["supporting_evidence"], list)
        assert isinstance(contract["contradicting_evidence"], list)

    def test_next_steps_contain_no_remediation(self) -> None:
        """Read-only engine: recommendations are investigation steps only."""
        _result, finding = _scored_finding(scenario_unknown_destination_records())
        steps = " ".join(output_contract_of(finding)["recommended_next_steps"]).lower()
        for verb in ("delete", "revoke", "block", "disable", "quarantine", "detach"):
            assert verb not in steps, f"remediation verb {verb!r} leaked into next steps"


class TestDashboardView:
    def test_view_exposes_required_panels(self) -> None:
        records = scenario_abnormal_enumeration()
        detector = DataExfiltrationDetector(
            profiler=BehavioralProfiler(),
            arde_validator=ARDEValidator(),
        )
        result = detector.process_events(cloudtrail_records=records)
        scored = detector.score_sessions(result, ScoringStack(variant="B"))
        finding = scored[0]
        session = result.sessions[0]
        events = [EventNormalizer().normalize_cloudtrail(r) for r in records]
        fset = result.behavioral_features[0]

        view = build_dashboard_view(
            finding, session=session, scored=scored[0], fset=fset, events=events,
        )
        for key in (
            "severity", "risk_score", "confidence", "robustness_score",
            "validation_status", "actor", "resource", "session",
            "temporal_context", "data_volume", "sensitivity", "destination",
            "access_timeline", "normal_vs_observed", "top_signals",
            "supporting_evidence", "contradicting_evidence", "recommended_next_steps",
            "versions",
        ):
            assert key in view, key
        assert view["normal_vs_observed"]["available"] is True
        assert len(view["normal_vs_observed"]["dimensions"]) == 9
        # every session event appears on the timeline
        assert len(view["access_timeline"]) == session.event_count == len(events)

    def test_view_is_json_serializable(self) -> None:
        _result, finding = _scored_finding(scenario_normal_s3_access())
        view = build_dashboard_view(finding, session=_result.sessions[0])
        json.dumps(view, sort_keys=True)


def scenario_unknown_destination_records():
    from .fixtures.scenarios import scenario_unknown_destination

    return scenario_unknown_destination()
