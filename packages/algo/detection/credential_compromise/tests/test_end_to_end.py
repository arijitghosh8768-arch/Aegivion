"""End-to-end and security tests for the final finding (ARDE-integrated)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from detection.credential_compromise.anomaly import IsolationForest
from detection.credential_compromise.config import AnomalyConfig, DetectorConfig
from detection.credential_compromise.detector import (
    CredentialCompromiseDetector,
    DetectionMode,
)
from detection.credential_compromise.schemas import Severity

MONDAY = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)


def persona_event(seq, *, identity, at, **overrides):
    from detection.credential_compromise.schemas import (
        BaselineCategory,
        EventCategory,
        IdentityActivityEvent,
        IdentityKind,
        PrincipalType,
    )

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
            overrides[field_name] = overrides.pop(shortcut)
    payload = dict(
        event_id=f"e2e-{seq:06d}",
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
        ingest_time=at,
    )
    payload.update(overrides)
    return IdentityActivityEvent(**payload)


def _learned_detector(identity: str) -> CredentialCompromiseDetector:
    detector = CredentialCompromiseDetector(config=DetectorConfig())
    detector.learn(
        [
            persona_event(i, identity=identity, at=MONDAY + timedelta(days=i % 14, hours=10))
            for i in range(300)
        ]
    )
    return detector


def _kill_chain(identity: str, seq: int = 901) -> object:
    return persona_event(
        seq,
        identity=identity,
        at=MONDAY + timedelta(days=20, hours=3),
        country="KP",
        ip="45.12.98.7",
        asn=131279,
        ua="python-requests/2.31",
        service="iam",
        family="IAM_PRIVILEGE_MUTATION",
        access="write",
        privilege=True,
        mfa=False,
        event_name="PutUserPolicy",
    )


class TestEndToEndFinding:
    def test_final_finding_contains_full_schema(self):
        identity = "aws:1:user:e2e-schema"
        detector = _learned_detector(identity)
        result = detector.detect(_kill_chain(identity), mode=DetectionMode.REPLAY)
        assert result.is_finding
        finding = result.finding

        required = {
            "finding_type", "severity", "risk_score", "confidence",
            "robustness_score", "identity_key", "session_key", "first_seen",
            "last_seen", "signals", "evidence", "supporting_features",
            "contradicting_features", "baseline_quality", "model_versions",
            "rule_versions", "recommended_next_steps", "ATTACK_mapping",
            "arde", "explanation", "validation_status",
        }
        assert required <= set(finding), required - set(finding)
        assert finding["finding_type"] == "credential_compromise"
        assert 0.0 <= finding["robustness_score"] <= 100.0
        assert finding["validation_status"] in (
            "PASSED", "PASSED_WITH_WARNINGS", "REVIEW_REQUIRED", "REJECTED"
        )

    def test_finding_is_deterministic_across_detector_instances(self):
        identity = "aws:1:user:e2e-determinism"
        first = _learned_detector(identity)
        second = _learned_detector(identity)
        f1 = first.detect(_kill_chain(identity)).finding
        f2 = second.detect(_kill_chain(identity)).finding
        assert f1 is not None and f2 is not None
        # Everything except the audit-linked free fields must be identical.
        for key in f1:
            if key in ("last_seen", "first_seen"):
                continue  # timestamps derive from event data; compare anyway
            assert f1[key] == f2[key], f"field {key} differs"

        # Even timestamps are event-derived, so they must match too.
        assert f1["first_seen"] == f2["first_seen"]
        assert f1["last_seen"] == f2["last_seen"]

    def test_arde_runs_inside_detector_and_audits(self):
        identity = "aws:1:user:e2e-arde"
        detector = _learned_detector(identity)
        result = detector.detect(_kill_chain(identity))
        assert result.arde is not None
        assert len(result.arde.checks) == 10
        # The audit trail recorded the validated finding.
        assert any(
            entry.action == "finding.validated" for entry in detector.audit_log.entries()
        )
        ok, broken = detector.audit_log.verify()
        assert ok and broken is None

    def test_ml_corroborated_finding_stamps_model_versions(self):
        identity = "aws:1:user:e2e-ml"
        detector = _learned_detector(identity)
        # Train the forest on the benign history rows (synthetic but unsupervised).
        import random

        from detection.credential_compromise.anomaly import build_feature_vector
        from detection.credential_compromise.features import extract_features
        from detection.credential_compromise.temporal import TemporalTracker, burst_score

        config = detector.config
        profile = detector._profiles[(identity, 30)]
        tracker = TemporalTracker()
        rows = []
        for i in range(300):
            event = persona_event(i, identity=identity, at=MONDAY + timedelta(days=i % 14, hours=10))
            windows = tracker.window_slices(identity, at=event.timestamp)
            burst = burst_score(windows.get(5), windows.get(60))
            features = extract_features(event, profile, config=config.baseline, feature_config=config.features)
            rows.append(
                build_feature_vector(
                    event, features, windows=windows, burst=burst, config=config.scoring
                ).values
            )
            tracker.observe(event)
        forest = IsolationForest(AnomalyConfig(trees=40, subsample_size=64)).fit(rows)
        detector.anomaly_model = forest

        result = detector.detect(_kill_chain(identity))
        assert result.is_finding
        assert result.finding["model_versions"]["model_name"] == "isolation_forest"
        # Anomaly score now participates in the evidence trail.
        assert result.anomaly_score is not None
        explanation = result.finding["explanation"]
        assert explanation["model_agreement"] in ("FULL", "PARTIAL", "NONE")


class TestSafeResponse:
    def test_recommended_steps_never_include_remediation_actions(self):
        forbidden = (
            "disable", "revoke", "delete", "remove", "isolate",
            "quarantine", "detach policy", "modify iam",
        )
        identity = "aws:1:user:e2e-safe"
        detector = _learned_detector(identity)
        finding = detector.detect(_kill_chain(identity)).finding
        assert finding is not None
        steps = [str(step).lower() for step in finding["recommended_next_steps"]]
        for step in steps:
            for word in forbidden:
                assert word not in step, f"remediation leaked into detection: {step}"
        # The detector never mutates anything beyond its own evidence state.
        assert detector.config.ingest.provider in ("aws",)

    def test_suppressed_finding_leaves_audit_trail_not_silence(self):
        identity = "aws:1:user:e2e-suppressed"
        detector = _learned_detector(identity)
        detector.suppression.add(
            scope="identity",
            scope_value=identity,
            reason="approved travel window",
            created_by="analyst-1",
        )
        result = detector.detect(_kill_chain(identity))
        # LOW/MEDIUM would be hidden, but a HIGH/CRITICAL finding is only
        # downgraded - and always audited either way.
        assert any(
            entry.action == "finding.validated"
            for entry in detector.audit_log.entries()
        )
        if result.is_finding:
            assert result.finding is not None
        else:
            assert result.suppression is not None
            assert result.suppression.matched_suppression_ids
