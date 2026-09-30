"""Robustness / adversarial tests.

The detector must not become excessively confident when telemetry is
corrupted, missing, forged, or contradictory. All scenarios are
synthetic: they corrupt in-memory copies of fixtures, never real
telemetry, and never touch infrastructure.
"""

from __future__ import annotations

from algo.data_exfiltration.data_exfiltration.arde.robustness import (
    RobustnessHarness,
    RobustnessScenario,
)
from algo.data_exfiltration.data_exfiltration.arde.validator import ARDEValidator
from algo.data_exfiltration.data_exfiltration.intelligence.feature_set import FeatureAvailability

from algo.data_exfiltration.data_exfiltration.arde.models import ValidationStatus

from .test_arde_validator import _finding, _fset, _scored, _session


class TestAdversarialScenarios:
    def _run_full_suite(self, scored=None, fset=None):
        validator = ARDEValidator()
        harness = RobustnessHarness(validator)
        report = harness.run(
            session=_session(egress_bytes=500_000.0, destinations=["198.51.100.9"]),
            scored=scored or _scored(risk=0.7),
            fset=fset or _fset(volume=0.8, destination=0.6),
            finding=_finding(),
        )
        return report

    def test_all_nine_scenario_families_run(self) -> None:
        report = self._run_full_suite()
        names = {r.scenario for r in report.results}
        assert {
            "missing_destination_fields",
            "missing_byte_counts",
            "corrupted_timestamps",
            "future_timestamps",
            "missing_actor_identity",
            "inflated_request_counts",
            "contradictory_telemetry_sources",
            "noisy_location_metadata",
            "baseline_contamination",
        } <= names

    def test_no_excessive_confidence_anywhere(self) -> None:
        report = self._run_full_suite()
        assert report.passed, [f.scenario for f in report.failures]

    def test_corrupted_timestamps_rejected(self) -> None:
        validator = ARDEValidator()
        harness = RobustnessHarness(validator)
        report = harness.run(
            session=_session(),
            scored=_scored(risk=0.5),
            fset=_fset(),
            finding=_finding(),
            scenarios=[
                RobustnessScenario(
                    name="corrupted_timestamps",
                    description="end before start",
                    corruptor=lambda s: s.model_copy(deep=True, update={})
                    or s,
                )
            ],
        )
        # use the built-in corruptor instead for the real assertion
        report = harness.run(
            session=_session(),
            scored=_scored(risk=0.5),
            fset=_fset(),
            finding=_finding(),
        )
        corrupted = [r for r in report.results if r.scenario == "corrupted_timestamps"]
        assert corrupted and corrupted[0].corrupted_status == "REJECTED"

    def test_inflated_requests_do_not_raise_confidence(self) -> None:
        report = self._run_full_suite()
        inflated = [r for r in report.results if r.scenario == "inflated_request_counts"]
        assert inflated
        assert inflated[0].corrupted_robustness <= inflated[0].base_robustness + 1e-9

    def test_contradictory_sources_flagged(self) -> None:
        validator = ARDEValidator()
        harness = RobustnessHarness(validator)
        report = harness.run(
            session=_session(),
            scored=_scored(risk=0.5),
            fset=_fset(),
            finding=_finding(),
        )
        contradictory = [r for r in report.results if r.scenario == "contradictory_telemetry_sources"]
        assert contradictory
        # must not silently pass
        assert contradictory[0].corrupted_status in (
            "PASSED_WITH_WARNINGS", "REVIEW_REQUIRED", "REJECTED",
        )

    def test_missing_destination_fields_never_pass_cleanly(self) -> None:
        report = self._run_full_suite()
        missing = [r for r in report.results if r.scenario == "missing_destination_fields"]
        assert missing
        assert missing[0].corrupted_status != "PASSED"

    def test_report_dict_serializable(self) -> None:
        report = self._run_full_suite()
        payload = report.as_dict()
        assert payload["scenario_count"] == len(report.results)
        assert payload["passed"] is True


class TestExceptionIntegration:
    def test_matching_exception_requires_review_and_is_audited(self) -> None:
        """The core no-silent-suppression contract: a matched exception
        keeps the finding visible and routes it to review."""
        from algo.data_exfiltration.data_exfiltration.arde.approved_activities import (
            ApprovedActivityKind,
            ApprovedActivityProfile,
            ApprovedActivityRegistry,
        )
        from algo.data_exfiltration.data_exfiltration.arde.audit import AuditLog

        registry = ApprovedActivityRegistry([
            ApprovedActivityProfile(
                profile_id="aap-backup",
                name="nightly backup",
                kind=ApprovedActivityKind.BACKUP_JOB,
                actor_patterns=["arn:aws:sts::*:assumed-role/BackupOperator/*"],
                resources=["s3://backups-prod"],
                max_bytes=6 * 1024**3,
            )
        ])
        log = AuditLog()
        validator = ARDEValidator(exceptions=registry, audit_log=log)
        session = _session(
            actor="arn:aws:sts::111122223333:assumed-role/BackupOperator/backup-job-42",
            resources=["s3://backups-prod"],
        )
        finding = _finding(severity=None)
        outcome = validator.validate(finding, session=session, scored=_scored(risk=0.6), fset=_fset(volume=0.9))

        matched = [r for r in outcome.exceptions_applied if r["matched"]]
        assert matched, "backup exception must match"
        # not PASSED silently: review is required
        assert outcome.validation_status is ValidationStatus.REVIEW_REQUIRED
        # audit has it
        assert log.verify()
        entry = log.entries[0]
        assert any(
            e["profile_id"] == "aap-backup" for e in entry.payload["exceptions_matched"]
        )

    def test_exception_with_disabling_returns_to_full_scrutiny(self) -> None:
        from algo.data_exfiltration.data_exfiltration.arde.approved_activities import (
            ApprovedActivityKind,
            ApprovedActivityProfile,
            ApprovedActivityRegistry,
        )
        registry = ApprovedActivityRegistry([
            ApprovedActivityProfile(
                profile_id="aap-backup",
                name="nightly backup",
                kind=ApprovedActivityKind.BACKUP_JOB,
                actor_patterns=["arn:aws:sts::*:assumed-role/BackupOperator/*"],
                resources=["s3://backups-prod"],
            )
        ])
        validator = ARDEValidator(exceptions=registry)
        session = _session(
            actor="arn:aws:sts::111122223333:assumed-role/BackupOperator/backup-job-42",
            resources=["s3://backups-prod"],
        )
        kwargs = dict(session=session, scored=_scored(risk=0.6), fset=_fset(volume=0.9))

        before = validator.validate(_finding(), **kwargs)
        assert any(r["matched"] for r in before.exceptions_applied)

        registry.disable("aap-backup")
        after = validator.validate(_finding(), **kwargs)
        assert not any(r["matched"] for r in after.exceptions_applied)


class TestContaminationDetection:
    def test_baseline_contamination_scenario_runs(self) -> None:
        harness = RobustnessHarness(ARDEValidator())
        report = harness.run(
            session=_session(),
            scored=_scored(risk=0.5),
            fset=_fset(volume=0.9, scope="peer", baseline_quality=0.3),
            finding=_finding(),
        )
        contamination = [r for r in report.results if r.scenario == "baseline_contamination"]
        assert contamination
        # inflating baseline trust must not reduce scrutiny
        assert contamination[0].excessive_confidence is False
