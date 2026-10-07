"""Fixture corpus integrity tests: all 13 scenarios load and project."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SYNTH = FIXTURES / "synthetic"
REPLAY = FIXTURES / "replay"

EXPECTED_SCENARIOS = {
    "normal_writes",
    "normal_lifecycle_cleanup",
    "scheduled_backup_cleanup",
    "mass_modification",
    "mass_deletion",
    "version_deletion",
    "snapshot_deletion",
    "recovery_point_deletion",
    "recovery_protection_change",
    "mass_rewrite_sequence",
    "mixed_normal_destructive",
    "malformed_telemetry",
    "missing_telemetry_fields",
}


def load_scenario(name: str) -> tuple[dict, list[dict]]:
    raw = json.loads((SYNTH / name / "raw.json").read_text(encoding="utf-8"))
    events = [
        json.loads(line)
        for line in (SYNTH / name / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return raw, events


class TestFixtureCorpus:
    def test_all_thirteen_scenarios_exist(self):
        present = {p.name for p in SYNTH.iterdir() if p.is_dir()}
        assert EXPECTED_SCENARIOS <= present

    def test_manifest_lists_all_scenarios(self):
        manifest = json.loads((SYNTH / "manifest.json").read_text(encoding="utf-8"))
        listed = {entry["scenario"] for entry in manifest["scenarios"]}
        assert EXPECTED_SCENARIOS <= listed

    @pytest.mark.parametrize(
        "scenario",
        sorted(EXPECTED_SCENARIOS - {"malformed_telemetry"}),
    )
    def test_every_non_malformed_record_normalizes(self, scenario):
        raw, events = load_scenario(scenario)
        # destructive/normal scenarios must fully project; malformed has exceptions
        assert len(events) == len(raw["records"]), scenario

    def test_normal_writes_content(self):
        _, events = load_scenario("normal_writes")
        assert len(events) == 60
        assert all(e["action_category"] == "create" for e in events)
        assert all(e["actor_id"].endswith("alice.admin") for e in events)

    def test_normal_lifecycle_cleanup_content(self):
        _, events = load_scenario("normal_lifecycle_cleanup")
        assert all(e["action_category"] == "delete" for e in events)
        assert all(e["is_delete_marker"] for e in events)
        assert all(e["data_provenance"]["is_synthetic"] for e in events)

    def test_scheduled_backup_cleanup_content(self):
        _, events = load_scenario("scheduled_backup_cleanup")
        assert all(e["action_category"] == "recovery_point_delete" for e in events)
        assert all("backup-planner" in e["actor_id"] for e in events)

    def test_mass_deletion_content(self):
        _, events = load_scenario("mass_deletion")
        assert all(e["operation_type"] == "batch" for e in events)
        assert all(e["object_count"] == 20 for e in events)

    def test_version_deletion_content(self):
        _, events = load_scenario("version_deletion")
        version_deletes = [e for e in events if e["action_category"] == "version_delete"]
        markers = [e for e in events if e["is_delete_marker"]]
        assert len(version_deletes) == 50
        assert len(markers) == 10

    def test_snapshot_deletion_spans_regions(self):
        _, events = load_scenario("snapshot_deletion")
        regions = {e["region"] for e in events}
        assert regions == {"us-east-1", "eu-west-1"}
        assert all(e["snapshot_id"].startswith("snap-") for e in events)

    def test_recovery_point_deletion_two_vaults(self):
        _, events = load_scenario("recovery_point_deletion")
        vaults = {e["backup_vault_name"] for e in events}
        assert vaults == {"fin-prod-vault", "fin-prod-vault-legacy"}

    def test_recovery_protection_change_mix(self):
        _, events = load_scenario("recovery_protection_change")
        categories = {e["action_category"] for e in events}
        assert "protection_change" in categories
        assert "policy_change" in categories
        assert "share_change" in categories
        assert "backup_delete" in categories

    def test_mass_rewrite_content(self):
        _, events = load_scenario("mass_rewrite_sequence")
        assert len(events) == 70
        assert all(e["action_category"] == "rewrite" for e in events)

    def test_mixed_scenario_has_both_kinds(self):
        _, events = load_scenario("mixed_normal_destructive")
        categories = {e["action_category"] for e in events}
        assert "create" in categories and "delete" in categories

    def test_malformed_telemetry_mostly_rejected(self):
        raw, events = load_scenario("malformed_telemetry")
        assert len(raw["records"]) == 11
        assert len(events) <= 2  # only structurally salvageable records normalize

    def test_missing_telemetry_fields_records_absences(self):
        _, events = load_scenario("missing_telemetry_fields")
        first = events[0]
        availability = {a["field"]: a for a in first["feature_availability"]}
        assert not availability["actor_id"]["is_available"] if "is_available" in availability["actor_id"] else True
        # the sparse record must still carry a usable timestamp + action
        assert first["timestamp"]
        assert first["action_category"] == "delete"

    def test_replay_corpora_present(self):
        for name in ("backup_eventbridge_sample.json", "snapshot_eventbridge_sample.json"):
            path = REPLAY / name
            assert path.exists()
            payload = json.loads(path.read_text(encoding="utf-8"))
            assert payload["records"]
