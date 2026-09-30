"""Raw-record persistence: temp-store + provenance verification.

Verifies the "raw events are never discarded" guarantee: every normalized
event keeps a verifiable link to the original payload, with secrets
redacted before storage.
"""

from __future__ import annotations

import json

from algo.data_exfiltration.data_exfiltration.normalizer import EventNormalizer
from algo.data_exfiltration.data_exfiltration.raw_store import RawEventStore


def test_raw_store_roundtrip(tmp_path) -> None:
    store = RawEventStore(base_dir=tmp_path)
    ref = store.store({"eventName": "GetObject", "x": 1})
    assert store.load(ref) == {"eventName": "GetObject", "x": 1}


def test_store_digest_is_verifiable(tmp_path) -> None:
    store = RawEventStore(base_dir=tmp_path)
    ref = store.store({"a": 1})
    ref2 = store.store({"a": 1})
    assert ref != ref2  # unique references even for identical payloads
    # digest recorded alongside the payload matches recomputation
    entry = json.loads((tmp_path / f"{ref}.json").read_text())
    assert store.verify(ref, entry["record"]["payload"]) is True


def test_store_digest_detects_tampering(tmp_path) -> None:
    store = RawEventStore(base_dir=tmp_path)
    ref = store.store({"a": 1})
    assert store.verify(ref, {"a": 2}) is False


def test_normalizer_persists_raw_and_links_reference(tmp_path) -> None:
    from .fixtures.cloudtrail_records import S3_GET

    store = RawEventStore(base_dir=tmp_path)
    event = EventNormalizer().normalize_cloudtrail(S3_GET, raw_store=store)
    assert event.raw_event_reference is not None
    assert store.verify(event.raw_event_reference, S3_GET) is True
    stored = store.load(event.raw_event_reference)
    assert stored["eventName"] == "GetObject"


def test_normalizer_without_store_keeps_no_reference() -> None:
    from .fixtures.cloudtrail_records import S3_GET

    event = EventNormalizer().normalize_cloudtrail(S3_GET)
    assert event.raw_event_reference is None
