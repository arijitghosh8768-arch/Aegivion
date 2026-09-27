"""Tests for replay, detector orchestration and the three-way comparison."""

from __future__ import annotations

from datetime import timedelta

import pytest

from detection.credential_compromise.config import DetectorConfig
from detection.credential_compromise.detector import (
    CredentialCompromiseDetector,
    DetectionMode,
)
from detection.credential_compromise.model_registry import (
    ComponentVersions,
    model_card_for,
    rule_fingerprint,
)
from detection.credential_compromise.replay import (
    Metrics,
    compare_configurations,
    format_comparison_report,
    synthetic_dataset,
    temporal_split,
)


@pytest.fixture(scope="module")
def dataset():
    events, labels = synthetic_dataset(n_identities=6, n_benign_per_identity=60, seed=99)
    return temporal_split(events, labels, train_fraction=0.6)


def test_synthetic_dataset_has_both_classes():
    events, labels = synthetic_dataset(n_identities=4, n_benign_per_identity=40, seed=5)
    assert set(labels) == {0, 1}
    assert labels.count(1) > 0 and labels.count(0) > 0
    # Sorted for causal replay.
    timestamps = [event.timestamp for event in events]
    assert timestamps == sorted(timestamps)


def test_temporal_split_is_chronological_and_disjoint(dataset):
    train, test = dataset
    assert train and test
    assert train[-1][0].timestamp <= test[0][0].timestamp
    train_ids = {event.event_id for event, _ in train}
    test_ids = {event.event_id for event, _ in test}
    assert not (train_ids & test_ids)


def _persona_event(seq, *, identity, at, **overrides):
    """Local copy of the persona event factory (avoids cross-test imports)."""
    from detection.credential_compromise.schemas import (
        BaselineCategory,
        EventCategory,
        IdentityActivityEvent,
        IdentityKind,
        PrincipalType,
    )

    payload = dict(
        event_id=f"re-{seq:06d}",
        timestamp=at,
        principal_id=identity,
        principal_name=identity.split(":")[-1],
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
        identity_key=identity,
        account_id="123456789012",
        event_source="s3.amazonaws.com",
        event_name="GetObject",
        event_category=EventCategory.DATA,
        service_name="s3",
        api_family="S3_DATA_READ",
        read_or_write="read",
        privilege_change=False,
        source_ip="10.20.30.40",
        country="IN",
        asn=9829,
        user_agent="aws-cli/2.13.0",
        mfa_authenticated=True,
    )
    # Accept persona-style shortcuts and translate them to schema fields.
    translation = {
        "ip": "source_ip",
        "service": "service_name",
        "ua": "user_agent",
        "family": "api_family",
        "access": "read_or_write",
        "privilege": "privilege_change",
        "mfa": "mfa_authenticated",
    }
    for shortcut, field_name in translation.items():
        if shortcut in overrides:
            payload[field_name] = overrides.pop(shortcut)
    payload.update(overrides)
    return IdentityActivityEvent(**payload)


def test_detector_real_time_produces_finding_on_kill_chain():
    config = DetectorConfig()
    detector = CredentialCompromiseDetector(config=config)
    from datetime import datetime, timezone

    monday = datetime(2026, 6, 1, tzinfo=timezone.utc)
    identity = "aws:1:user:victim-rt"
    benign = [
        _persona_event(
            i,
            identity=identity,
            at=monday + timedelta(days=i % 14, hours=10),
        )
        for i in range(300)
    ]
    detector.learn(benign)
    attack = _persona_event(
        901,
        identity=identity,
        at=monday + timedelta(days=20, hours=3),
        country="KP",
        ip="45.12.98.7",
        asn=131279,
        user_agent="python-requests/2.31",
        service="iam",
        api_family="IAM_PRIVILEGE_MUTATION",
        read_or_write="write",
        privilege_change=True,
        mfa_authenticated=False,
    )
    result = detector.detect(attack, mode=DetectionMode.REAL_TIME)
    assert result.is_finding
    assert result.finding is not None
    assert result.finding["severity"] in ("HIGH", "CRITICAL")
    assert result.confidence < 1.0  # risk and confidence are separate values
    assert "R001" in {s.rule_id for s in result.signals}


def test_replay_is_deterministic(dataset):
    config = DetectorConfig()
    train, test = dataset
    detector = CredentialCompromiseDetector(config=config)
    by_identity: dict[str, list] = {}
    for event, label in train:
        if label == 0:
            by_identity.setdefault(event.identity_key, []).append(event)
    for identity, events in by_identity.items():
        detector.learn(events)

    events = [event for event, _ in test]
    first = detector.replay(events)
    second = CredentialCompromiseDetector(config=config)
    for identity, evs in by_identity.items():
        second.learn(evs)
    second_run = second.replay(events)
    assert [r.risk for r in first] == [r.risk for r in second_run]


def test_high_risk_event_does_not_poison_detector_baseline():
    from datetime import datetime, timezone

    monday = datetime(2026, 6, 1, tzinfo=timezone.utc)
    identity = "aws:1:user:poison-guard"
    detector = CredentialCompromiseDetector(config=DetectorConfig())
    detector.learn(
        [
            _persona_event(i, identity=identity, at=monday + timedelta(days=i % 14, hours=10))
            for i in range(300)
        ]
    )
    before = detector._profiles[(identity, 30)].normal_countries

    attack = _persona_event(
        902,
        identity=identity,
        at=monday + timedelta(days=20, hours=3),
        country="KP",
        ip="45.12.98.7",
        service="iam",
        api_family="IAM_PRIVILEGE_MUTATION",
        read_or_write="write",
        privilege_change=True,
        mfa_authenticated=False,
    )
    result = detector.detect(attack)
    detector.observe_baseline(attack, event_risk=result.risk)
    after = detector._profiles[(identity, 30)].normal_countries
    assert before == after  # high-risk observations are excluded from learning


def test_comparison_report_quantifies_three_configurations(dataset):
    config = DetectorConfig()
    train, test = dataset
    results = compare_configurations(config=config, train=train, test=test)
    assert set(results) == {
        "A: rules only",
        "B: rules + baseline",
        "C: rules + baseline + ML",
    }
    for scenario in results.values():
        assert scenario.metrics.true_positives + scenario.metrics.false_negatives > 0
    report = format_comparison_report(results)
    for name in results:
        assert name in report
    assert "SYNTHETIC" in report  # honesty note is mandatory


def test_versions_are_stamped():
    versions = ComponentVersions(baseline_version=7)
    payload = versions.to_dict()
    assert payload["baseline_version"] == 7
    assert payload["feature_version"].startswith("fv")
    assert payload["rule_version"].startswith("rules-")
    card = model_card_for(training_rows=100, synthetic_labels=True, label_source="synthetic")
    assert card.synthetic_labels is True
    assert "R001" in rule_fingerprint()


def test_metrics_math():
    metrics = Metrics(
        true_positives=8, false_positives=2, false_negatives=2, true_negatives=88
    )
    assert metrics.precision == 0.8
    assert metrics.recall == 0.8
    assert metrics.f1 == 0.8
    assert metrics.false_positive_rate == pytest.approx(2 / 90, abs=1e-4)
    empty = Metrics()
    assert empty.precision is None and empty.f1 is None
