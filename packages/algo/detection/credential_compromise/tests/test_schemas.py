"""Schema and redaction tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from detection.credential_compromise.schemas import (
    IdentityActivityEvent,
    fingerprint_secret,
    mask_secret,
    normalize_ip,
)


def test_naive_timestamp_is_coerced_to_utc(make_event):
    event = make_event(timestamp=datetime(2026, 9, 20, 4, 12, 33))
    assert event.timestamp.tzinfo is not None
    assert event.timestamp == datetime(2026, 9, 20, 4, 12, 33, tzinfo=timezone.utc)


def test_aware_timestamp_is_converted_to_utc(make_event):
    event = make_event(timestamp=datetime(2026, 9, 20, 9, 42, 33, tzinfo=timezone.utc))
    assert event.timestamp.tzinfo == timezone.utc


def test_valid_ip_is_canonicalised(make_event):
    event = make_event(source_ip="49.36.12.44")
    assert event.source_ip == "49.36.12.44"


def test_ip_with_port_is_stripped(make_event):
    event = make_event(source_ip="203.0.113.77:443")
    assert event.source_ip == "203.0.113.77"


def test_invalid_ip_is_rejected(make_event):
    with pytest.raises(ValidationError):
        make_event(source_ip="not-an-ip")


def test_normalize_ip_edge_cases():
    assert normalize_ip(None) is None
    assert normalize_ip("") is None
    assert normalize_ip("  2001:db8::1 ") == "2001:db8::1"
    with pytest.raises(ValueError):
        normalize_ip("AWS Internal")


def test_extra_fields_are_forbidden(make_event):
    with pytest.raises(ValidationError):
        make_event(unexpected_field="nope")


@pytest.mark.parametrize("field", ["event_id", "event_source", "event_name", "service_name"])
def test_required_strings_cannot_be_empty(make_event, field):
    with pytest.raises(ValidationError):
        make_event(**{field: "   "})


def test_mask_secret_hides_the_middle():
    masked = mask_secret("AKIAEXAMPLEDEVKEY")
    assert masked is not None
    assert masked.startswith("AKIA")
    assert masked.endswith("EVKEY")
    assert "EXAMPLE" not in masked


def test_mask_secret_short_value():
    assert mask_secret("abcd") == "****"
    assert mask_secret(None) is None


def test_fingerprint_is_stable_and_salted():
    first = fingerprint_secret("AKIAEXAMPLEDEVKEY", salt="s1")
    second = fingerprint_secret("AKIAEXAMPLEDEVKEY", salt="s1")
    other = fingerprint_secret("AKIAEXAMPLEDEVKEY", salt="s2")
    assert first == second
    assert first != other
    assert first is not None and len(first) == 64
    assert fingerprint_secret(None) is None


def test_access_keys_never_appear_in_logs(make_event):
    event = make_event(access_key_id="AKIAEXAMPLEDEVKEY")
    log_view = event.to_log_dict()
    assert log_view["access_key_id"] != "AKIAEXAMPLEDEVKEY"
    assert "AKIAEXAMPLEDEVKEY" not in repr(event)
    assert "AKIAEXAMPLEDEVKEY" not in str(event.to_log_dict())


def test_event_repr_identifies_without_leaking(make_event):
    event = make_event(access_key_id="AKIAEXAMPLEDEVKEY")
    assert event.event_id in repr(event)
    assert event.event_name in repr(event)


def test_event_defaults_are_conservative(make_event):
    event = make_event()
    assert event.privilege_change is False
    assert event.mfa_authenticated is None
    assert event.normalization_warnings == ()
    assert event.country is None and event.asn is None
