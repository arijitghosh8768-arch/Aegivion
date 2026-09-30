"""Security tests + end-to-end detector integration for the ARDE layer.

Security invariants enforced here:
- ARDE is detection-only: no infrastructure actions, no deletions, no
  revocations, no blocking (source-level guarantee, regression-guarded);
- findings are never deleted or suppressed silently — REJECTED findings
  remain visible with capped severity;
- exception profiles cannot be unscoped;
- audit chain detects tampering;
- validation metadata survives finding serialization.
"""

from __future__ import annotations

import pytest

from algo.data_exfiltration.data_exfiltration.arde import ARDEValidator, AuditLog
from algo.data_exfiltration.data_exfiltration.arde.approved_activities import ApprovedActivityRegistry
from algo.data_exfiltration.data_exfiltration.arde.integration import (
    explanation_of,
    outcome_of,
    report_of,
    validate_and_attach,
)
from algo.data_exfiltration.data_exfiltration.arde.models import ValidationStatus
from algo.data_exfiltration.data_exfiltration.detector import DataExfiltrationDetector

from .fixtures import scenarios as sc
from .test_arde_validator import _finding, _fset, _scored, _session


# ---------------------------------------------------------------------------
# security invariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_arde_source_never_performs_remediation_actions(self) -> None:
        """Regression guard: the ARDE package must not contain
        remediation-style operations. Detection only."""
        import re
        from pathlib import Path

        arde_dir = Path(__file__).resolve().parents[1] / "arde"
        forbidden = re.compile(
            r"(\bdelete_bucket\b|\bblock_ip\b|\brevoke_user\b|\bdisable_user\b|"
            r"\bput_bucket_policy\b|\bdetach_role_policy\b|\bstop_instance\b|"
            r"\bdelete_object\b|\bquarantine\b)",
            re.IGNORECASE,
        )
        offenders = []
        for path in arde_dir.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            # docstring mentions of the constraint are fine; code is not
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
                    continue
                if forbidden.search(line):
                    offenders.append((path.name, line.strip()))
        assert not offenders, offenders

    def test_rejected_finding_remains_visible(self) -> None:
        """REJECTED is an assessment, not a deletion."""
        validator = ARDEValidator()
        finding = _finding(severity=None)
        session = _session(
            start_ms=_finding().observed_at_epoch_ms + 10 * 365.25 * 24 * 3600 * 1000.0,
            end_ms=_finding().observed_at_epoch_ms + 10 * 365.25 * 24 * 3600 * 1000.0 + 1000.0,
        )
        outcome = validator.validate(finding, session=session, scored=_scored(), fset=_fset())
        assert outcome.validation_status is ValidationStatus.REJECTED
        # the finding object still exists, untouched, with full metadata
        assert finding.finding_id
        assert finding.title

    def test_unscoped_exception_profile_rejected(self) -> None:
        registry = ApprovedActivityRegistry()
        with pytest.raises(ValueError):
            registry.register(
                __import__(
                    "algo.data_exfiltration.data_exfiltration.arde.approved_activities",
                    fromlist=["ApprovedActivityProfile"],
                ).ApprovedActivityProfile(
                    profile_id="broad",
                    name="broad",
                    actor_patterns=[],
                    resources=[],
                )
            )

    def test_exception_cannot_be_broadened_to_all_resources(self) -> None:
        from algo.data_exfiltration.data_exfiltration.arde.approved_activities import (
            ApprovedActivityKind,
            ApprovedActivityProfile,
        )

        with pytest.raises(ValueError, match="resource scope"):
            registry = ApprovedActivityRegistry()
            registry.register(
                ApprovedActivityProfile(
                    profile_id="sneaky",
                    name="sneaky",
                    kind=ApprovedActivityKind.BACKUP_JOB,
                    actor_patterns=["arn:*"],
                    resources=[],
                    resource_prefixes=[],
                )
            )

    def test_tampered_audit_chain_detected(self) -> None:
        log = AuditLog()
        validator = ARDEValidator(audit_log=log)
        validator.validate(_finding(), session=_session(), scored=_scored(), fset=_fset())
        validator.validate(_finding(finding_id="find-2"), session=_session(), scored=_scored(), fset=_fset())
        log.entries[0].validation_status = "PASSED"  # tamper
        assert log.verify() is False

    def test_audit_records_are_bound_to_content(self) -> None:
        log = AuditLog()
        validator = ARDEValidator(audit_log=log)
        outcome = validator.validate(_finding(), session=_session(), scored=_scored(), fset=_fset())
        entry = log.entries[0]
        assert entry.payload["robustness_score"] == outcome.robustness_score
        assert len(entry.payload["checks"]) == 10
        assert entry.entry_hash == entry.compute_hash()

    def test_validation_metadata_survives_serialization(self) -> None:
        finding = _finding()
        validate_and_attach(
            finding, session=_session(), scored=_scored(), fset=_fset()
        )
        payload = finding.model_dump_json()
        assert "arde_validation" in payload
        assert "arde_explanation" in payload


# ---------------------------------------------------------------------------
# integration: validate_and_attach
# ---------------------------------------------------------------------------


class TestValidateAndAttach:
    def test_attach_writes_metadata_and_applies_downgrade(self) -> None:
        from algo.data_exfiltration.data_exfiltration.schemas import FindingSeverity

        finding = _finding(severity=FindingSeverity.CRITICAL)
        session = _session(
            start_ms=_finding().observed_at_epoch_ms + 10 * 365.25 * 24 * 3600 * 1000.0,
            end_ms=_finding().observed_at_epoch_ms + 10 * 365.25 * 24 * 3600 * 1000.0 + 1000.0,
        )
        outcome = validate_and_attach(
            finding, session=session, scored=_scored(), fset=_fset()
        )
        assert outcome.validation_status is ValidationStatus.REJECTED
        assert finding.metadata["arde_validation"]["downgrade_applied"] is True
        assert finding.severity is FindingSeverity.MEDIUM
        # typed accessors round-trip
        assert outcome_of(finding).finding_id == finding.finding_id
        assert explanation_of(finding).finding_id == finding.finding_id
        report = report_of(finding)
        assert "FINDING REPORT" in report

    def test_attach_without_scored_still_validates(self) -> None:
        """Part 1 discovery findings (no scores) still get validated on
        the evidence alone."""
        finding = _finding()
        outcome = validate_and_attach(finding, session=_session())
        assert outcome.validation_status is not None
        assert finding.metadata["arde_validation"]["validation_status"]


# ---------------------------------------------------------------------------
# end-to-end: detector pipeline with ARDE
# ---------------------------------------------------------------------------


def _detector_with_arde(**kwargs):
    audit = AuditLog()
    validator = ARDEValidator(audit_log=audit, **kwargs)
    detector = DataExfiltrationDetector(arde_validator=validator, arde_audit_log=audit)
    return detector, audit


class TestDetectorARDEIntegration:
    def test_detector_without_arde_unchanged(self) -> None:
        """No ARDE components -> metadata untouched (Part 1 behavior)."""
        detector = DataExfiltrationDetector()
        result = detector.process_events(cloudtrail_records=sc.scenario_normal_s3_access())
        assert len(result.findings) == 1
        assert "arde_validation" not in result.findings[0].metadata

    def test_detector_with_arde_validates_all_findings(self) -> None:
        detector, audit = _detector_with_arde()
        result = detector.process_events(cloudtrail_records=sc.scenario_normal_s3_access())
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert "arde_validation" in finding.metadata
        assert "arde_explanation" in finding.metadata
        outcome = outcome_of(finding)
        assert outcome is not None
        assert len(outcome.checks) == 10
        assert audit.verify() is True
        assert len(audit) == 1

    def test_detector_audit_covers_whole_batch(self) -> None:
        records = (
            sc.scenario_normal_s3_access()
            + sc.scenario_sensitive_access()
        )
        detector, audit = _detector_with_arde()
        result = detector.process_events(cloudtrail_records=records)
        assert len(result.findings) >= 2
        assert len(audit) == len(result.findings)
        assert audit.verify() is True

    def test_scenario_9_incomplete_telemetry_not_passed(self) -> None:
        """Missing-telemetry sessions must not sail through as PASSED."""
        detector, _audit = _detector_with_arde()
        result = detector.process_events(cloudtrail_records=sc.scenario_incomplete_telemetry())
        for finding in result.findings:
            outcome = outcome_of(finding)
            assert outcome.validation_status in (
                ValidationStatus.PASSED_WITH_WARNINGS,
                ValidationStatus.REVIEW_REQUIRED,
                ValidationStatus.REJECTED,
            )
            explanation = explanation_of(finding)
            assert explanation.unavailable_telemetry, "gaps must be listed"

    def test_explanation_of_discovery_finding_is_evidence_only(self) -> None:
        """Part 1 discovery findings carry no risk; the explanation must
        not invent one."""
        detector, _audit = _detector_with_arde()
        result = detector.process_events(cloudtrail_records=sc.scenario_normal_s3_access())
        explanation = explanation_of(result.findings[0])
        assert explanation.top_contributors == []  # no contributions exist
        assert result.findings[0].risk_score is None

    def test_finding_persists_with_validation_metadata(self) -> None:
        from algo.data_exfiltration.data_exfiltration.storage import DetectionRepository

        repo = DetectionRepository("sqlite:///:memory:")
        audit = AuditLog()
        validator = ARDEValidator(audit_log=audit)
        detector = DataExfiltrationDetector(repository=repo, arde_validator=validator, arde_audit_log=audit)
        result = detector.process_events(cloudtrail_records=sc.scenario_normal_s3_access())
        stored = repo.list_findings()
        assert stored
        payload = stored[0].arde  # ARDE payload untouched
        assert payload["arde_version"] == "1.0"
        metadata = stored[0].metadata
        assert "arde_validation" in metadata
