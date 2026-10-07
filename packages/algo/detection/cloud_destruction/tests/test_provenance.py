"""Provenance + availability model tests (deliverable #6)."""

from __future__ import annotations

from algo.detection.cloud_destruction.provenance import (
    AvailabilityTracker,
    DataProvenance,
    FieldAvailability,
    Measurement,
    UnavailableReason,
    ValuePresence,
    availability_for_missing,
    build_availability,
)


class TestFieldAvailability:
    def test_available_when_presence_not_unavailable(self):
        record = FieldAvailability(field="actor_id", presence=ValuePresence.AVAILABLE)
        assert record.is_available

    def test_unavailable_default(self):
        record = FieldAvailability(field="actor_id")
        assert not record.is_available
        assert record.reason is UnavailableReason.NOT_IN_SOURCE


class TestAvailabilityTracker:
    def test_available_and_unavailable(self):
        tracker = AvailabilityTracker()
        tracker.available("event_id")
        tracker.unavailable("object_key", UnavailableReason.FIELD_NOT_APPLICABLE, detail="n/a")
        records = {r.field: r for r in tracker.to_tuple()}
        assert records["event_id"].is_available
        assert not records["object_key"].is_available
        assert records["object_key"].reason is UnavailableReason.FIELD_NOT_APPLICABLE
        assert records["object_key"].detail == "n/a"

    def test_derived_and_enriched_presence(self):
        tracker = AvailabilityTracker()
        tracker.available("resource_type", derived=True)
        tracker.available("business_criticality", enriched=True)
        by_presence = {r.field: r.presence for r in tracker.to_tuple()}
        assert by_presence["resource_type"] is ValuePresence.DERIVED
        assert by_presence["business_criticality"] is ValuePresence.ENRICHED

    def test_merge_existing_wins(self):
        first = AvailabilityTracker()
        first.available("actor_id")
        second = AvailabilityTracker()
        second.unavailable("actor_id", UnavailableReason.PARSE_FAILURE)
        second.available("region")
        first.merge(second)
        records = {r.field: r for r in first.to_tuple()}
        assert records["actor_id"].is_available  # existing entry wins
        assert records["region"].is_available

    def test_sorted_deterministic_output(self):
        tracker = AvailabilityTracker()
        tracker.available("zulu")
        tracker.available("alpha")
        assert [r.field for r in tracker.to_tuple()] == ["alpha", "zulu"]


class TestHelpers:
    def test_build_availability(self):
        records = build_availability(
            ["event_id", "actor_id"], present={"event_id": "x", "actor_id": None}
        )
        by_field = {r.field: r for r in records}
        assert by_field["event_id"].is_available
        assert not by_field["actor_id"].is_available

    def test_availability_for_missing(self):
        records = availability_for_missing(["a", "b"], UnavailableReason.ENRICHMENT_MISSING)
        assert all(not r.is_available for r in records)
        assert all(r.reason is UnavailableReason.ENRICHMENT_MISSING for r in records)


class TestDataProvenance:
    def test_defaults(self):
        provenance = DataProvenance()
        assert provenance.source_type == "cloudtrail"
        assert not provenance.is_replayed
        assert not provenance.is_synthetic
        assert provenance.normalizer_version

    def test_with_note_is_immutable_copy(self):
        provenance = DataProvenance()
        updated = provenance.with_note("coerced timestamp")
        assert updated.transformation_notes == ("coerced timestamp",)
        assert provenance.transformation_notes == ()

    def test_replay_and_synthetic_flags(self):
        provenance = DataProvenance(
            source_type="replay", is_replayed=True, replay_source="fixtures/synthetic"
        )
        assert provenance.is_replayed
        assert provenance.replay_source == "fixtures/synthetic"


class TestMeasurement:
    def test_unavailable_measurement(self):
        measurement = Measurement()
        assert not measurement.is_available
        assert measurement.value is None

    def test_available_measurement(self):
        measurement = Measurement(value=42.0, source="tests")
        assert measurement.is_available
        assert measurement.value == 42.0
