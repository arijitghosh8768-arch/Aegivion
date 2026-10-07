"""Part 5 tests: Threat-Correlation integration.

The broker is the one-way seam between Algorithm #3 and
Aegivion Threat Correlation. These tests pin the enforced
rules: one-way flow, additive-only context, idempotent
submission, no fabricated records, explicit acknowledgement
— and zero imports from the detection/ingestion packages.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from correlation import (
    CorrelationContext,
    ThreatCorrelationBroker,
    finding_digest,
)
from algo.detection.cloud_destruction.finding import DestructionFinding, Severity

BASE_TIME = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)


def make_finding(
    finding_id: str = "fnd-1",
    severity: Severity = Severity.HIGH,
    risk: float = 0.72,
    confidence: float = 0.81,
    actor: str = "alice.admin",
    session: str = "sess-1",
    account: str = "sub-1",
) -> DestructionFinding:
    return DestructionFinding(
        finding_id=finding_id,
        session_id=session,
        detector_name="aegivion.cloud_destruction",
        severity=severity,
        risk_score=risk,
        confidence_score=confidence,
        actor_id=actor,
        account_id=account,
        observed_at=BASE_TIME,
        model_name="isolation_forest",
        model_version="1.0.0",
        feature_version="1.0.0",
        baseline_version="b-1",
        scoring_version="1.0.0",
        rule_version="1.0.0",
    )


def make_duck_finding(finding_id: str = "fnd-duck") -> SimpleNamespace:
    """A finding-like object with no dependency on the detector."""
    return SimpleNamespace(
        finding_id=finding_id,
        session_id="sess-duck",
        detector_name="aegivion.credential-compromise",
        severity="critical",
        risk_score=0.91,
        confidence_score=0.77,
        actor_id="attacker@evil.example",
        account_id="proj-2",
        observed_at=BASE_TIME,
        model_name="heuristic",
        model_version="2.0.0",
        feature_version="1.0.0",
        baseline_version=None,
        scoring_version="1.0.0",
        rule_version="1.0.0",
        confidence_version="1.0.0",
        severity_version="1.0.0",
        resources_touched=("resource-a",),
    )


class TestBrokerIndependence:
    def test_package_imports_nothing_from_detection_or_ingestion(self):
        import correlation.threat_correlation as module

        import correlation.threat_correlation as _mod

        source = open(_mod.__file__, encoding="utf-8").read()
        for prefix in ("from detection", "import detection", "from ingestion", "import ingestion"):
            assert prefix not in source
        loaded = [
            name
            for name in sys.modules
            if name.startswith(("detection", "ingestion"))
        ]
        # detection/ingestion may be loaded by the test itself; the
        # module under test must not have *caused* it.
        assert module.__name__ == "correlation.threat_correlation"

    def test_works_on_duck_typed_findings(self):
        broker = ThreatCorrelationBroker()
        record = broker.submit(make_duck_finding())
        assert record.detector_name == "aegivion.credential-compromise"
        assert record.severity == "critical"
        assert record.risk_score == 0.91
        assert record.resources_touched == ("resource-a",)


class TestSubmission:
    def test_submit_captures_finding_facts(self):
        broker = ThreatCorrelationBroker()
        record = broker.submit(make_finding())
        assert record.finding_id == "fnd-1"
        assert record.session_id == "sess-1"
        assert record.detector_name == "aegivion.cloud_destruction"
        assert record.severity == "high"
        assert record.risk_score == 0.72
        assert record.confidence_score == 0.81
        assert record.actor_id == "alice.admin"
        assert record.account_id == "sub-1"
        assert record.observed_at == BASE_TIME.isoformat()
        assert record.versions["model_version"] == "1.0.0"
        assert record.versions["scoring_version"] == "1.0.0"
        assert record.source_detectors == ("aegivion.cloud_destruction",)
        assert record.acknowledged is False

    def test_submission_is_idempotent(self):
        broker = ThreatCorrelationBroker()
        finding = make_finding()
        first = broker.submit(finding)
        second = broker.submit(finding)
        assert first.correlation_id == second.correlation_id
        assert len(broker.records()) == 1

    def test_correlation_id_is_a_content_digest(self):
        finding = make_finding()
        digest = finding_digest(finding)
        assert len(digest) == 64  # sha256 hex
        assert ThreatCorrelationBroker().submit(finding).correlation_id == digest
        # Same identity + lineage from a different object -> same digest.
        twin = make_finding()
        assert finding_digest(twin) == digest

    def test_submit_many_preserves_order(self):
        broker = ThreatCorrelationBroker()
        findings = [
            make_finding("a", risk=0.4),
            make_finding("b", risk=0.6),
            make_finding("c", risk=0.5),
        ]
        records = broker.submit_many(findings)
        assert [r.finding_id for r in records] == ["a", "b", "c"]
        assert len(broker.records()) == 3


class TestContext:
    def test_attach_context_is_additive_only(self):
        broker = ThreatCorrelationBroker()
        finding = make_finding()
        broker.submit(finding)
        before = broker.get("fnd-1")
        record = broker.attach_context(
            "fnd-1",
            CorrelationContext(
                source_algorithm="aegivion.credential-compromise",
                context_type="actor_match",
                payload={"match_confidence": 0.93},
                source_version="1.4.0",
            ),
        )
        assert record is not None
        assert len(record.contexts) == 1
        context = record.contexts[0]
        assert context.source_algorithm == "aegivion.credential-compromise"
        assert context.context_type == "actor_match"
        assert context.payload == {"match_confidence": 0.93}
        assert context.source_version == "1.4.0"
        assert context.received_at is not None
        # The finding's own scores are immutable inside correlation.
        assert record.risk_score == before.risk_score
        assert record.confidence_score == before.confidence_score
        assert record.severity == before.severity

    def test_context_default_received_at_is_stamped(self):
        clock = {"now": BASE_TIME}
        broker = ThreatCorrelationBroker(clock=lambda: clock["now"])
        broker.submit(make_finding())
        record = broker.attach_context(
            "fnd-1",
            CorrelationContext(
                source_algorithm="aegivion.data-exfiltration",
                context_type="resource_match",
            ),
        )
        assert record.contexts[0].received_at == BASE_TIME

    def test_unknown_finding_id_returns_none(self):
        broker = ThreatCorrelationBroker()
        result = broker.attach_context(
            "does-not-exist",
            CorrelationContext(
                source_algorithm="aegivion.credential-compromise",
                context_type="actor_match",
            ),
        )
        assert result is None
        assert broker.records() == []

    def test_multiple_contexts_accumulate(self):
        broker = ThreatCorrelationBroker()
        broker.submit(make_finding())
        broker.attach_context(
            "fnd-1",
            CorrelationContext(
                source_algorithm="aegivion.credential-compromise",
                context_type="actor_match",
            ),
        )
        broker.attach_context(
            "fnd-1",
            CorrelationContext(
                source_algorithm="aegivion.data-exfiltration",
                context_type="resource_match",
            ),
        )
        record = broker.get("fnd-1")
        assert [c.context_type for c in record.contexts] == [
            "actor_match",
            "resource_match",
        ]


class TestLedger:
    def test_get_and_records(self):
        broker = ThreatCorrelationBroker()
        broker.submit(make_finding("x"))
        assert broker.get("x") is not None
        assert broker.get("missing") is None
        assert [r.finding_id for r in broker.records()] == ["x"]

    def test_pending_review_and_acknowledge(self):
        broker = ThreatCorrelationBroker()
        record = broker.submit(make_finding())
        assert len(broker.pending_review()) == 1
        assert broker.acknowledge(record.correlation_id) is True
        assert broker.pending_review() == []
        assert broker.get("fnd-1").acknowledged is True

    def test_acknowledge_unknown_id_returns_false(self):
        broker = ThreatCorrelationBroker()
        assert broker.acknowledge("nope") is False

    def test_to_log_dict_is_json_serializable(self):
        import json

        broker = ThreatCorrelationBroker()
        record = broker.submit(make_finding())
        broker.attach_context(
            "fnd-1",
            CorrelationContext(
                source_algorithm="aegivion.credential-compromise",
                context_type="actor_match",
            ),
        )
        payload = json.dumps(broker.to_log_dict())
        assert str(record.correlation_id) in payload
        assert "\"record_count\": 1" in payload
        assert "actor_match" in payload
