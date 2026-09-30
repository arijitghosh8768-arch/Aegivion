"""Destination intelligence + sequence analyzer tests."""

from __future__ import annotations

from algo.data_exfiltration.data_exfiltration.enrichment import DestinationClass, classify_destination, normalize_destination
from algo.data_exfiltration.data_exfiltration.intelligence.destination_intelligence import (
    KnownUniverse,
    assess_destinations,
)
from algo.data_exfiltration.data_exfiltration.intelligence.sequence import (
    build_ngram_model,
    score_sequence,
)
from algo.data_exfiltration.data_exfiltration.session import SessionBuilder
from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer

from .fixtures.cloudtrail_records import S3_GET, S3_LIST


class TestClassifyDestination:
    def test_trusted_internal(self) -> None:
        cls, _ = classify_destination(ip="10.1.2.3")
        assert cls is DestinationClass.TRUSTED_INTERNAL

    def test_high_risk_external(self) -> None:
        cls, reason = classify_destination(ip="203.0.113.50")
        assert cls is DestinationClass.HIGH_RISK_EXTERNAL
        assert "cidr" in reason

    def test_known_cloud_by_asn(self) -> None:
        cls, _ = classify_destination(ip="52.1.2.3", asn="16509")
        assert cls is DestinationClass.KNOWN_CLOUD

    def test_known_cloud_approved_list(self) -> None:
        cls, reason = classify_destination(asn="15169", known_cloud_providers={"google"})
        assert cls is DestinationClass.KNOWN_CLOUD
        assert "approved" in reason

    def test_known_business_by_destination_ip(self) -> None:
        cls, _ = classify_destination(ip="198.18.0.9", known_destinations={"198.18.0.9"})
        assert cls is DestinationClass.KNOWN_BUSINESS

    def test_known_business_by_domain(self) -> None:
        cls, _ = classify_destination(domain="vendor.example.com", known_domains={"example.com"})
        assert cls is DestinationClass.KNOWN_BUSINESS

    def test_unknown_external(self) -> None:
        cls, _ = classify_destination(ip="198.18.0.9")
        assert cls is DestinationClass.UNKNOWN_EXTERNAL

    def test_unavailable_without_any_information(self) -> None:
        cls, _ = classify_destination()
        assert cls is DestinationClass.UNAVAILABLE


def test_normalize_destination() -> None:
    assert normalize_destination("S3.Eu-West-1.Amazonaws.com.") == "amazonaws.com"
    assert normalize_destination("example.co.uk") == "example.co.uk"
    assert normalize_destination(None) is None


class TestDestinationNovelty:
    def _session_with(self, destinations: list[str]):
        # fabricate a session directly through the model
        from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession

        return DataAccessSession(
            session_id="s1",
            actor_id="a",
            unique_destinations=destinations,
        )

    def test_new_destination_is_evidence_not_malicious(self) -> None:
        known = KnownUniverse(destinations={"198.18.0.5"})
        session = self._session_with(["198.18.0.5", "198.18.0.9"])
        result = assess_destinations(session, known)
        assert result.destination_novelty == 0.5  # one of two public destinations is new
        # classification records it as unknown external, not "attack"
        assert result.worst_class == DestinationClass.UNKNOWN_EXTERNAL.value

    def test_unsupplied_universe_is_unavailable_not_zero(self) -> None:
        session = self._session_with(["198.18.0.9"])
        result = assess_destinations(session, KnownUniverse())
        assert result.destination_novelty is None
        assert result.detail["known_universe_supplied"]["destinations"] is False

    def test_internal_destinations_exempt_from_novelty(self) -> None:
        known = KnownUniverse(destinations=set())
        session = self._session_with(["10.0.0.5", "192.168.1.5"])
        result = assess_destinations(session, known)
        assert result.destination_novelty == 0.0
        assert result.worst_class == DestinationClass.TRUSTED_INTERNAL.value


class TestSequence:
    def test_familiar_sequence_scores_zero(self) -> None:
        history = [
            ["list", "read_object", "read_object", "read_object"],
        ] * 5
        result = score_sequence(["list", "read_object", "read_object"], history)
        assert result.access_sequence_score == 0.0
        assert result.availability == "observed"

    def test_novel_sequence_scores_high(self) -> None:
        history = [["read_object", "read_object"]] * 10
        result = score_sequence(["list", "enumerate", "copy"], history)
        assert result.access_sequence_score == 1.0
        assert result.novel_ngrams

    def test_cold_start_is_not_suspicious(self) -> None:
        result = score_sequence(["list", "read_object"], [])
        assert result.access_sequence_score is None
        assert result.availability == "cold_start"

    def test_no_signatures_required(self) -> None:
        """Deviation is statistical: never-seen bigrams score, familiar do not."""
        history = [["list", "read_object"], ["list", "read_object"], ["write_object", "write_object"]]
        model = build_ngram_model(history)
        assert model.get(("list", "read_object")) == 2
        result = score_sequence(["list", "read_object"], history)
        assert result.access_sequence_score == 0.0


def _events_for(actions: list[str], actor: str, start_h: int) -> list:
    from datetime import datetime, timedelta, timezone
    from algo.data_exfiltration.data_exfiltration.schemas import DataAction

    base = datetime(2024, 11, 14, start_h, 0, tzinfo=timezone.utc)
    name_map = {
        "list": "ListObjectsV2",
        "read": "GetObject",
        "write": "PutObject",
        "copy": "CopyObject",
    }
    events = []
    for i, action in enumerate(actions):
        rec = {
            **S3_GET,
            "eventTime": (base + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventName": name_map[action],
        }
        events.append(EventNormalizer().normalize_cloudtrail(rec))
    return events
