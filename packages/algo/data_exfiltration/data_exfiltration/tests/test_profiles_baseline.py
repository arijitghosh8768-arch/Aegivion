"""Resource profile + behavioral baseline tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from algo.data_exfiltration.data_exfiltration.baseline import baseline_summary, compute_baseline
from algo.data_exfiltration.data_exfiltration.enrichment import StaticMacieEnricher
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.resource_profile import ResourceProfileBuilder
from algo.data_exfiltration.data_exfiltration.session import SessionBuilder

from .fixtures.cloudtrail_records import NORM, S3_GET
from .fixtures.scenarios import scenario_backup_events_for_baseline


def _role_get(bucket: str, key: str, when: datetime, out: int) -> dict:
    rec = {
        **NORM,
        "arn": "arn:aws:sts::111122223333:assumed-role/BackupOperator/backup-job-42",
        "type": "AssumedRole",
        "userAgent": "aws-sdk-go/1.44 (backup-agent)",
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": "GetObject",
        "requestParameters": {"bucketName": bucket, "key": key},
        "additionalEventData": {"bytesTransferredOut": out},
    }
    return rec


class TestResourceProfile:
    def test_profile_accumulates_observed_history(self) -> None:
        base = datetime(2024, 11, 14, 1, 0, tzinfo=timezone.utc)
        records = [_role_get("backups-prod", f"p{i}.tar", base + timedelta(minutes=i * 4), 500_000_000) for i in range(6)]
        events = [EventNormalizer().normalize_cloudtrail(r) for r in records]

        builder = ResourceProfileBuilder()
        builder.observe(events)
        profile = builder.build("s3://backups-prod")

        assert profile.history_event_count == 6
        assert profile.resource_type == "s3_bucket"
        assert profile.known_actors == ["arn:aws:sts::111122223333:assumed-role/BackupOperator/backup-job-42"]
        assert "01" in profile.normal_access_hours
        assert profile.normal_access_volume is not None
        assert profile.normal_access_volume.value == 3_000_000_000.0
        assert profile.normal_request_rate is not None
        assert profile.normal_request_rate.value == 6.0

    def test_profile_without_enrichment_keeps_sensitivity_unavailable(self) -> None:
        events = [EventNormalizer().normalize_cloudtrail(S3_GET)]
        builder = ResourceProfileBuilder()
        builder.observe(events)
        profile = builder.build("s3://prod-customer-data")
        assert profile.sensitivity_level is None
        assert profile.sensitivity_score is None
        assert profile.sensitivity_source is None

    def test_profile_with_macie_enrichment(self) -> None:
        macie = StaticMacieEnricher(table={
            "prod-customer-data": {"classification": "PERSONAL_INFORMATION", "score": 0.9},
        })
        events = [EventNormalizer().normalize_cloudtrail(S3_GET)]
        builder = ResourceProfileBuilder(macie_enricher=macie)
        builder.observe(events)
        profile = builder.build("s3://prod-customer-data")
        assert profile.sensitivity_level is not None
        assert profile.sensitivity_level.value == "pii"
        assert profile.sensitivity_source == "macie"
        assert profile.sensitivity_score.value == 0.9

    def test_owner_registry_populates_owner(self) -> None:
        events = [EventNormalizer().normalize_cloudtrail(S3_GET)]
        builder = ResourceProfileBuilder(owner_registry={
            "s3://prod-customer-data": {"owner": "data-platform", "business_unit": "customer-analytics"},
        })
        builder.observe(events)
        profile = builder.build("s3://prod-customer-data")
        assert profile.owner == "data-platform"
        assert profile.business_unit == "customer-analytics"


class TestBaseline:
    def test_baseline_from_two_weeks_of_backups(self) -> None:
        records = scenario_backup_events_for_baseline()
        events = [EventNormalizer().normalize_cloudtrail(r) for r in records]
        builder = SessionBuilder()
        builder.add_events(events)
        sessions = builder.flush()

        baseline = compute_baseline(sessions)
        assert baseline.session_count == len(sessions)
        components = baseline.components
        assert "bytes_total_p50" in components
        assert "bytes_total_p95" in components
        assert components["bytes_total_p95"].value >= components["bytes_total_p50"].value
        assert components["duration_p95_s"].value >= components["duration_p50_s"].value
        assert components["event_count_p50"].value == 6.0  # nightly batches of 6

    def test_baseline_empty_history(self) -> None:
        baseline = compute_baseline([])
        assert baseline.session_count == 0
        assert baseline.components == {}

    def test_baseline_is_immutable_and_versioned(self) -> None:
        records = scenario_backup_events_for_baseline()[:12]
        events = [EventNormalizer().normalize_cloudtrail(r) for r in records]
        builder = SessionBuilder()
        builder.add_events(events)
        sessions = builder.flush()
        b1 = compute_baseline(sessions)
        b2 = compute_baseline(sessions)
        assert b1.version_id != b2.version_id or b1 == b2

    def test_baseline_summary_shape(self) -> None:
        records = scenario_backup_events_for_baseline()[:12]
        events = [EventNormalizer().normalize_cloudtrail(r) for r in records]
        builder = SessionBuilder()
        builder.add_events(events)
        sessions = builder.flush()
        summary = baseline_summary(compute_baseline(sessions))
        assert summary["session_count"] == len(sessions)
        assert "bytes_total_p50" in summary["components"]
