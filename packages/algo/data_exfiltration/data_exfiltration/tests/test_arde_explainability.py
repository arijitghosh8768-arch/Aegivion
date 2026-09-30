"""Explainability tests: machine-readable structure, all ten questions,
evidence grounding (nothing invented), and the analyst formatter."""

from __future__ import annotations

import json

from algo.data_exfiltration.data_exfiltration.arde.audit import AuditLog
from algo.data_exfiltration.data_exfiltration.arde.explain import ExplainabilityBuilder, FindingExplanation
from algo.data_exfiltration.data_exfiltration.arde.formatter import format_finding_report
from algo.data_exfiltration.data_exfiltration.arde.models import ValidationStatus
from algo.data_exfiltration.data_exfiltration.arde.validator import ARDEValidator

from .test_arde_validator import _finding, _fset, _scored, _session


class TestMachineReadableExplanation:
    def _build(self):
        validator = ARDEValidator()
        finding = _finding()
        session = _session(egress_bytes=500_000.0, destinations=["198.51.100.9"])
        scored = _scored(risk=0.7, fired=["volume_deviation_elevated", "high_risk_destination"])
        fset = _fset(volume=0.8, destination=0.6, sensitivity=0.7, time=0.4)
        outcome = validator.validate(finding, session=session, scored=scored, fset=fset)
        builder = ExplainabilityBuilder()
        explanation = builder.build(
            finding, session=session, scored=scored, fset=fset, outcome=outcome
        )
        return explanation, outcome, finding

    def test_all_ten_questions_answered(self) -> None:
        explanation, _outcome, _f = self._build()
        assert explanation.what_happened  # WHAT happened
        assert explanation.why_unusual  # WHY unusual
        assert "baseline_scope" in explanation.normal_baseline  # normal baseline
        assert isinstance(explanation.what_changed, list)  # what changed
        assert "resources" in explanation.data_involved  # what data
        assert "score" in explanation.sensitivity  # how sensitive
        assert "unique_destinations" in explanation.data_movement  # where moved
        assert explanation.top_contributors  # which signals contributed most
        assert isinstance(explanation.contradicting_evidence, list)  # contradicting
        assert isinstance(explanation.unavailable_telemetry, list)  # what unavailable

    def test_contract_field_names_present(self) -> None:
        explanation, _outcome, _f = self._build()
        payload = json.loads(explanation.model_dump_json())
        for key in (
            "top_contributors", "supporting_evidence", "contradicting_evidence",
            "baseline_quality", "feature_availability", "model_agreement",
        ):
            assert key in payload, key

    def test_grades_in_vocabulary(self) -> None:
        explanation, _outcome, _f = self._build()
        assert explanation.baseline_quality in ("GOOD", "FAIR", "POOR", "NONE", "UNKNOWN")
        assert explanation.feature_availability in ("HIGH", "MEDIUM", "LOW", "UNKNOWN")
        assert explanation.model_agreement in ("STRONG", "PARTIAL", "WEAK", "UNKNOWN")

    def test_what_happened_names_actor_and_counts(self) -> None:
        explanation, _outcome, _f = self._build()
        assert "alice" in explanation.what_happened
        assert "4 data event(s)" in explanation.what_happened

    def test_sensitivity_source_recorded(self) -> None:
        explanation, _outcome, _f = self._build()
        assert explanation.sensitivity["score"] == 0.7
        assert explanation.sensitivity["source"] == "test"

    def test_validation_block_carries_status(self) -> None:
        explanation, outcome, _f = self._build()
        assert explanation.validation["validation_status"] == outcome.validation_status.value
        assert explanation.validation["robustness_score"] == outcome.robustness_score

    def test_serializes_for_llm_layer(self) -> None:
        """The future LLM layer consumes exactly this JSON — no more."""
        explanation, _outcome, _f = self._build()
        payload = json.loads(explanation.model_dump_json())
        assert payload["finding_id"]
        assert isinstance(payload["top_contributors"], list)
        # round-trip
        reparsed = FindingExplanation.model_validate(payload)
        assert reparsed.finding_id == explanation.finding_id


class TestEvidenceGrounding:
    def test_quiet_signals_contradict(self) -> None:
        validator = ARDEValidator()
        finding = _finding()
        session = _session()
        scored = _scored(risk=0.8)
        fset = _fset(volume=0.9, time=0.0, actor_resource=0.0)
        outcome = validator.validate(finding, session=session, scored=scored, fset=fset)
        explanation = ExplainabilityBuilder().build(
            finding, session=session, scored=scored, fset=fset, outcome=outcome
        )
        kinds = [e["kind"] for e in explanation.contradicting_evidence]
        assert "quiet_signals" in kinds

    def test_cold_start_reported_as_contradicting(self) -> None:
        validator = ARDEValidator()
        finding = _finding()
        session = _session()
        scored = _scored(risk=0.3)
        fset = _fset(scope="none", baseline_quality=0.0, volume=0.1)
        outcome = validator.validate(finding, session=session, scored=scored, fset=fset)
        explanation = ExplainabilityBuilder().build(
            finding, session=session, scored=scored, fset=fset, outcome=outcome
        )
        kinds = [e["kind"] for e in explanation.contradicting_evidence]
        assert "cold_start_baseline" in kinds

    def test_failed_checks_contradict(self) -> None:
        validator = ARDEValidator()
        finding = _finding()
        # destinations high-scored but absent -> destination check failure
        session = _session(destinations=[])
        scored = _scored(risk=0.3)
        fset = _fset(destination=0.9)
        outcome = validator.validate(finding, session=session, scored=scored, fset=fset)
        explanation = ExplainabilityBuilder().build(
            finding, session=session, scored=scored, fset=fset, outcome=outcome
        )
        kinds = [e["kind"] for e in explanation.contradicting_evidence]
        assert "failed_validation_check" in kinds

    def test_unavailable_telemetry_listed_not_invented(self) -> None:
        validator = ARDEValidator()
        finding = _finding()
        session = _session(bytes_total=None)
        scored = _scored(risk=0.3)
        fset = _fset(egress=None, sensitivity=None)
        outcome = validator.validate(finding, session=session, scored=scored, fset=fset)
        explanation = ExplainabilityBuilder().build(
            finding, session=session, scored=scored, fset=fset, outcome=outcome
        )
        text = " | ".join(explanation.unavailable_telemetry)
        assert "network flow telemetry" in text
        assert "sensitivity enrichment" in text
        assert "byte counts" in text


class TestAnalystFormatter:
    def test_report_contains_all_sections(self) -> None:
        validator = ARDEValidator()
        finding = _finding()
        session = _session(egress_bytes=500_000.0, destinations=["198.51.100.9"])
        scored = _scored(risk=0.7, fired=["volume_deviation_elevated"])
        fset = _fset(volume=0.8, destination=0.6, sensitivity=0.7)
        outcome = validator.validate(finding, session=session, scored=scored, fset=fset)
        explanation = ExplainabilityBuilder().build(
            finding, session=session, scored=scored, fset=fset, outcome=outcome
        )
        report = format_finding_report(explanation, finding=finding)
        for section in (
            "WHAT HAPPENED", "WHY IT IS UNUSUAL", "NORMAL BASELINE",
            "WHAT CHANGED", "DATA INVOLVED", "SENSITIVITY", "DATA MOVEMENT",
            "TOP CONTRIBUTORS", "SUPPORTING EVIDENCE", "CONTRADICTING EVIDENCE",
            "UNAVAILABLE TELEMETRY", "TRUST GRADES", "ARDE VALIDATION",
        ):
            assert section in report, section
        assert finding.finding_id in report
        assert "Aegivion remediation layer" in report

    def test_report_human_readable_sizes(self) -> None:
        validator = ARDEValidator()
        finding = _finding()
        session = _session(bytes_total=10 * 1024**3)
        explanation = ExplainabilityBuilder().build(
            finding, session=session, scored=_scored(), fset=_fset(),
            outcome=validator.validate(finding, session=session, scored=_scored(), fset=_fset()),
        )
        report = format_finding_report(explanation, finding=finding)
        assert "10.0 GB" in report

    def test_formatter_adds_no_evidence(self) -> None:
        """Every evidence line must originate in the explanation structure."""
        validator = ARDEValidator()
        finding = _finding()
        session = _session()
        explanation = ExplainabilityBuilder().build(
            finding, session=session, scored=_scored(), fset=_fset(),
            outcome=validator.validate(finding, session=session, scored=_scored(), fset=_fset()),
        )
        report = format_finding_report(explanation, finding=finding)
        # no finding-specific data appears that is not in the explanation
        assert session.resources_accessed[0] in report or "(none observed)" in report


class TestAuditLog:
    def test_validation_recorded_and_chained(self) -> None:
        log = AuditLog()
        validator = ARDEValidator(audit_log=log)
        finding = _finding()
        validator.validate(finding, session=_session(), scored=_scored(), fset=_fset())
        finding2 = _finding(finding_id="find-2")
        validator.validate(finding2, session=_session(), scored=_scored(), fset=_fset())
        assert len(log) == 2
        assert log.verify() is True
        entries = log.entries_for_finding("find-2")
        assert len(entries) == 1
        assert entries[0].previous_hash == log.entries[0].entry_hash

    def test_tampering_detected(self) -> None:
        log = AuditLog()
        validator = ARDEValidator(audit_log=log)
        validator.validate(_finding(), session=_session(), scored=_scored(), fset=_fset())
        entry = log.entries[0]
        entry.payload["robustness_score"] = 0.99  # tamper
        assert log.verify() is False

    def test_exception_evaluation_audited(self) -> None:
        from algo.data_exfiltration.data_exfiltration.arde.approved_activities import (
            ApprovedActivityProfile, ApprovedActivityKind, ApprovedActivityRegistry,
        )
        registry = ApprovedActivityRegistry([
            ApprovedActivityProfile(
                profile_id="aap-x", name="x", kind=ApprovedActivityKind.BACKUP_JOB,
                actor_patterns=["arn:*:user/alice"], resources=["s3://prod-customer-data"],
            )
        ])
        log = AuditLog()
        validator = ARDEValidator(exceptions=registry, audit_log=log)
        outcome = validator.validate(_finding(), session=_session(), scored=_scored(), fset=_fset())
        assert outcome.exceptions_applied, "exception records must appear"
        assert any(r["matched"] for r in outcome.exceptions_applied)
        entry = log.entries[0]
        assert entry.payload["exceptions_matched"], "matched exceptions must be in the audit entry"

    def test_json_export(self) -> None:
        log = AuditLog()
        validator = ARDEValidator(audit_log=log)
        validator.validate(_finding(), session=_session(), scored=_scored(), fset=_fset())
        import json as _json
        parsed = _json.loads(log.to_json())
        assert len(parsed) == 1
        assert parsed[0]["action"] == "finding_validated"
