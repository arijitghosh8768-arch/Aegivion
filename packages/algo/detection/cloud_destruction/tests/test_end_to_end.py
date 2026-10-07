"""End-to-end tests: raw telemetry -> canonical events -> sessions -> storage.

Runs the Part 1 foundation pipeline over every synthetic scenario and asserts
observational outcomes only. No scoring, no verdicts — Part 1 does not do that.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from algo.detection.cloud_destruction.config import DestructionDetectorConfig
from algo.detection.cloud_destruction.detector import DestructionDetector, FoundationPipeline
from algo.detection.cloud_destruction.normalizer import ResourceActivityNormalizer
from ingestion.aws.cloudtrail_resource_activity import (
    CloudTrailResourceActivityIngestor,
    IngestResult,
)
from algo.detection.cloud_destruction.session import DestructiveSessionBuilder
from algo.detection.cloud_destruction.storage import DestructionRepository
from algo.detection.cloud_destruction.schemas import ActionCategory

from algo.detection.cloud_destruction.tests.helpers import make_event

SYNTH = Path(__file__).resolve().parent / "fixtures" / "synthetic"


def load_raw(name: str) -> list[dict]:
    payload = json.loads((SYNTH / name / "raw.json").read_text(encoding="utf-8"))
    return payload["records"]


def normalize_all(records: list[dict]):
    normalizer = ResourceActivityNormalizer()
    events = []
    for index, record in enumerate(records):
        try:
            events.append(normalizer.normalize_cloudtrail(record))
        except Exception:
            continue  # malformed fixtures intentionally contribute nothing here
    return events


class TestScenarioE2E:
    def test_normal_writes_produce_benign_sessions(self):
        events = normalize_all(load_raw("normal_writes"))
        assert len(events) == 60
        sessions = DestructiveSessionBuilder().build_sessions(events)
        assert len(sessions) >= 1
        assert all(s.destructive_event_count == 0 for s in sessions)

    def test_mass_deletion_session_counters(self):
        events = normalize_all(load_raw("mass_deletion"))
        sessions = DestructiveSessionBuilder().build_sessions(events)
        assert len(sessions) == 1
        session = sessions[0]
        assert session.destructive_event_count == 4
        # batch deletes target buckets: 4 batches across 3 buckets
        assert session.unique_resource_count == 3
        assert len(session.deleted_resources) == 3

    def test_version_deletion_session(self):
        events = normalize_all(load_raw("version_deletion"))
        sessions = DestructiveSessionBuilder().build_sessions(events)
        assert len(sessions) == 1
        session = sessions[0]
        assert session.version_deletions == 50
        assert session.delete_marker_count == 10

    def test_snapshot_deletion_multi_region_sessions(self):
        events = normalize_all(load_raw("snapshot_deletion"))
        sessions = DestructiveSessionBuilder().build_sessions(events)
        # keyed by region -> us-east-1 and eu-west-1 sessions
        assert len(sessions) == 2
        total_snapshots = sum(s.snapshot_deletions for s in sessions)
        assert total_snapshots == 12

    def test_recovery_point_deletion_session(self):
        events = normalize_all(load_raw("recovery_point_deletion"))
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        assert session.backup_deletions == 10
        assert session.destructive_event_count == 10

    def test_protection_change_session(self):
        events = normalize_all(load_raw("recovery_protection_change"))
        session = DestructiveSessionBuilder().build_sessions(events)[0]
        assert session.protection_changes >= 9
        # 11 protection changes + 1 vault deletion; the 3 policy changes and
        # 1 share change are tracked but not destructive per the taxonomy.
        assert session.destructive_event_count == 12

    def test_mixed_scenario_separates_actors(self):
        events = normalize_all(load_raw("mixed_normal_destructive"))
        sessions = DestructiveSessionBuilder().build_sessions(events)
        actors = {s.actor_id for s in sessions}
        assert "arn:aws:sts::111122223333:assumed-role/devops-contractor/compromised-session" in actors
        benign = [s for s in sessions if s.actor_id != "arn:aws:sts::111122223333:assumed-role/devops-contractor/compromised-session"]
        assert any(s.destructive_event_count == 0 for s in benign)
        assert any(s.destructive_event_count > 0 for s in sessions)

    def test_foundation_pipeline_process(self):
        events = normalize_all(load_raw("normal_writes"))
        pipeline = FoundationPipeline(DestructionDetectorConfig())
        sessions, profiles = pipeline.process(events)
        assert sessions
        assert "fin-prod-reports" in profiles
        assert profiles["fin-prod-reports"].history_event_count == 60


class TestIngestionPipeline:
    def test_malformed_quarantined_end_to_end(self):
        ingestor = CloudTrailResourceActivityIngestor(strict=False)
        outcome: IngestResult = ingestor.ingest_batch(load_raw("malformed_telemetry"))
        assert outcome.quarantined
        assert outcome.events  # a couple of records are salvageable
        # every quarantined record retains the raw payload reference
        assert all("record" in q for q in outcome.quarantined)

    def test_missing_fields_scenario_normalizes_with_absences(self):
        ingestor = CloudTrailResourceActivityIngestor(strict=False)
        outcome = ingestor.ingest_batch(load_raw("missing_telemetry_fields"))
        assert len(outcome.events) == 5
        sparse = next(e for e in outcome.events if e.event_id == "sparse-001")
        availability = sparse.availability_map()
        assert not availability["actor_id"].is_available
        assert not availability["account_id"].is_available
        assert availability["action_category"].is_available

    def test_ingest_pipeline_persists(self):
        events = normalize_all(load_raw("normal_lifecycle_cleanup"))
        repo = DestructionRepository()
        repo.save_events(events)
        sessions = DestructiveSessionBuilder().build_sessions(events)
        repo.save_sessions(sessions)
        assert repo.count_events() == 50
        assert len(repo.list_sessions()) >= 1


class TestDetectorBoundary:
    def test_detector_requires_events(self):
        """Part 3: detect() is implemented and requires canonical events."""
        detector = DestructionDetector()
        with pytest.raises(TypeError):
            detector.detect()
        outcome = detector.detect([])
        assert outcome.findings == []

    def test_part1_produces_no_findings_tables_rows(self):
        repo = DestructionRepository()
        # no API exists to write findings — the table stays reserved
        from algo.detection.cloud_destruction.storage import DestructionFindingRow

        assert DestructionFindingRow.__tablename__ == "destruction_findings"


class TestTaxonomyAcrossScenarios:
    def test_no_fabricated_categories(self):
        valid = {c.value for c in ActionCategory}
        for scenario in sorted(p.name for p in SYNTH.iterdir() if p.is_dir()):
            path = SYNTH / scenario / "events.jsonl"
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                event = json.loads(line)
                assert event["action_category"] in valid, scenario
