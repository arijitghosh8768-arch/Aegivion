"""Exception hierarchy tests."""

from __future__ import annotations

import pytest

from detection.cloud_destruction.exceptions import (
    CloudDestructionError,
    ConfigurationError,
    DatabaseError,
    MalformedEventError,
    NotImplementedYetError,
    UnsupportedEventError,
)


class TestExceptionHierarchy:
    def test_all_derive_from_base(self):
        for exc_class in (
            ConfigurationError,
            DatabaseError,
            NotImplementedYetError,
        ):
            assert issubclass(exc_class, CloudDestructionError)

    def test_normalization_family(self):
        assert issubclass(MalformedEventError, CloudDestructionError)
        assert issubclass(UnsupportedEventError, CloudDestructionError)

    def test_context_rendering(self):
        error = ConfigurationError("bad combo", context={"left": 1, "right": 2})
        assert "left=1" in str(error)
        assert "right=2" in str(error)

    def test_malformed_event_tracks_missing_fields(self):
        error = MalformedEventError(
            "missing required fields", missing_fields=["eventID", "eventTime"]
        )
        assert error.missing_fields == ["eventID", "eventTime"]
        assert "eventID,eventTime" in str(error)

    def test_cause_preserved(self):
        original = ValueError("boom")
        error = MalformedEventError("wrapped", cause=original)
        assert error.cause is original
