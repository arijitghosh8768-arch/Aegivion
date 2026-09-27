"""Final acceptance test - the research brief's 13-step scenario.

Scenario: an identity normally operates from India during working hours using
Chrome and read-oriented APIs, then acts from a new country, new ASN, new IP,
new client, unusual hour, unusual API sequence and privilege-modification
APIs. The system must normalize, resolve, sessionize, deviate, signal, score,
validate (ARDE), explain, expose via API, preserve evidence, and remain
non-destructive - end to end, through the real Part 1 normalizer/resolver.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.server import Request, Router
from detection.credential_compromise.anomaly import IsolationForest
from detection.credential_compromise.arde import VALIDATION_STATUSES
from detection.credential_compromise.config import AnomalyConfig, DetectorConfig
from detection.credential_compromise.detector import (
    CredentialCompromiseDetector,
    DetectionMode,
)
from detection.credential_compromise.session import SessionTracker
from ingestion.aws.cloudtrail import CloudTrailNormalizer

UTC = timezone.utc
T0 = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
USER = "aniruddha"


def cloudtrail_record(seq: int, *, at: datetime, **overrides) -> dict:
    """A raw CloudTrail record (as the real ingestion path would receive)."""
    record = {
        "eventID": f"acc-{seq:07d}",
        "eventTime": at.isoformat().replace("+00:00", "Z"),
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "eventCategory": "dataEvent" if overrides.get("data") else "managementEvent",
        "recipientAccountId": ACCOUNT,
        "sourceIPAddress": "10.20.30.40",
        "userAgent": "Chrome/126 Windows",
        "userIdentity": {
            "type": "IAMUser",
            "accountId": ACCOUNT,
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{USER}",
            "userName": USER,
            "accessKeyId": "AKIAEXAMPLEDEVKEY",
        },
        "additionalEventData": {"MFAUsed": "Yes"},
    }
    record.update(overrides)
    return record


def _normal_records(n: int = 320) -> list[dict]:
    records = []
    for i in range(n):
        at = T0 + timedelta(days=i // 3, hours=9 + (i % 9), minutes=(i * 13) % 60)
        records.append(cloudtrail_record(i, at=at))
    return records


def _attack_records(start_seq: int = 900) -> list[dict]:
    base = T0 + timedelta(days=45, hours=3)
    steps = (
        ("iam.amazonaws.com", "GetAccountAuthorizationDetails", "10.20.30.40", "Chrome/126 Windows", "Yes"),
        ("sts.amazonaws.com", "AssumeRole", "45.12.98.7", "python-requests/2.31", "No"),
        ("iam.amazonaws.com", "PutUserPolicy", "45.12.98.7", "python-requests/2.31", "No"),
        ("iam.amazonaws.com", "CreateAccessKey", "45.12.98.7", "python-requests/2.31", "No"),
    )
    records = []
    for j, (source, name, ip, ua, mfa) in enumerate(steps):
        records.append(
            cloudtrail_record(
                start_seq + j,
                at=base + timedelta(minutes=4 * j),
                eventSource=source,
                eventName=name,
                sourceIPAddress=ip,
                userAgent=ua,
                userIdentity={
                    "type": "IAMUser",
                    "accountId": ACCOUNT,
                    "arn": f"arn:aws:iam::{ACCOUNT}:user/{USER}",
                    "userName": USER,
                    "accessKeyId": "AKIAEXAMPLEDEVKEY",
                },
                additionalEventData={"MFAUsed": mfa},
            )
        )
    return records


class TestAcceptanceScenario:
    @pytest.fixture(scope="class")
    def normalized(self):
        normalizer = CloudTrailNormalizer()
        result = normalizer.normalize_batch(_normal_records() + _attack_records(), strict=True)
        assert result.error_count == 0
        return result.events

    def test_step_1_3_normalization_identity_session(self, normalized):
        # Steps 1-3: normalize -> resolve -> session.
        assert len(normalized) == 324
        first = normalized[0]
        assert first.identity_key.startswith(f"aws:{ACCOUNT}:human_user:")
        assert first.identity_kind.value == "human"
        assert first.api_family == "S3_DATA_READ"

        tracker = SessionTracker()
        decision = tracker.add_event(first)
        assert decision.is_new_session

        # Feed a tight burst (2-minute gaps) that must stay one session...
        burst = [
            cloudtrail_record(7000 + j, at=T0 + timedelta(hours=10, minutes=2 * j))
            for j in range(10)
        ]
        from ingestion.aws.cloudtrail import CloudTrailNormalizer as _C
        burst_events = _C().normalize_batch(burst, strict=True).events
        for burst_event in burst_events:
            decision = tracker.add_event(burst_event)
        assert decision.session.event_count == 10

        # ...while events days apart must legitimately open new sessions
        # (idle timeout is 30 minutes by default).
        next_day = tracker.add_event(normalized[3])
        assert next_day.is_new_session

    def test_full_pipeline_produces_explainable_validated_finding(self, normalized):
        # Steps 4-10: deviations -> rules -> ML -> risk -> confidence -> ARDE -> finding.
        benign = [e for e in normalized if e.timestamp < T0 + timedelta(days=45)]
        attack = [e for e in normalized if e.timestamp >= T0 + timedelta(days=45)]

        detector = CredentialCompromiseDetector(config=DetectorConfig())
        detector.learn(benign)

        # Train the forest on benign rows (unsupervised; synthetic stream).
        from detection.credential_compromise.anomaly import build_feature_vector
        from detection.credential_compromise.features import extract_features
        from detection.credential_compromise.temporal import TemporalTracker, burst_score

        config = detector.config
        profile = detector._profiles[(benign[0].identity_key, 30)]
        tracker = TemporalTracker()
        rows = []
        for event in benign:
            windows = tracker.window_slices(event.identity_key, at=event.timestamp)
            burst = burst_score(windows.get(5), windows.get(60))
            features = extract_features(
                event, profile, config=config.baseline, feature_config=config.features
            )
            rows.append(
                build_feature_vector(
                    event, features, windows=windows, burst=burst,
                    config=config.scoring, profile=profile,
                ).values
            )
            tracker.observe(event)
        detector.anomaly_model = IsolationForest(AnomalyConfig(trees=40, subsample_size=64)).fit(rows)

        results = [detector.detect(e, mode=DetectionMode.REPLAY) for e in attack]
        findings = [r for r in results if r.is_finding]
        assert findings, "the kill chain must produce at least one finding"

        finding = findings[-1].finding
        # Step 10: explainable, validated finding with the full evidence set.
        assert finding["finding_type"] == "credential_compromise"
        assert finding["severity"] in ("HIGH", "CRITICAL")
        assert finding["validation_status"] in VALIDATION_STATUSES
        assert 0.0 <= finding["risk_score"] <= 100.0
        assert 0.0 <= finding["confidence"] <= 1.0
        assert 0.0 <= finding["robustness_score"] <= 100.0
        assert finding["explanation"]["top_contributors"]
        # The privilege/credential kill chain must appear in the evidence:
        # eight rules fire, so the top-5 contributor view legitimately
        # truncates - assert on the full supporting-evidence set instead.
        signal_ids = {s["rule_id"] for s in finding["signals"]}
        assert {"R010", "R012", "R013"} <= signal_ids
        supporting_labels = {
            e.get("label") for e in finding["explanation"]["supporting_evidence"]
        }
        assert {"Privilege modification", "MFA state anomaly"} <= supporting_labels
        assert finding["ATTACK_mapping"], "privilege mutation must map to ATT&CK"
        assert finding["model_versions"]["model_name"] == "isolation_forest"
        assert finding["rule_versions"]["rule_version"].startswith("rules-")

    def test_step_11_13_api_exposure_evidence_safety(self, normalized):
        # Steps 11-13: expose to Aegivion, preserve evidence, stay safe.
        router = Router()
        benign = [e for e in normalized if e.timestamp < T0 + timedelta(days=45)]
        attack = [e for e in normalized if e.timestamp >= T0 + timedelta(days=45)]

        detector = router.app.detector
        detector.learn(benign)
        finding_id = None
        for event in attack:
            response = router.handle(
                Request(method="POST", path="/api/v1/detections/credential-compromise/analyze",
                        body=event.model_dump(mode="json"))
            )
            assert response.status == 200
            if response.body.get("is_finding"):
                finding_id = response.body["finding_id"]

        assert finding_id, "the acceptance scenario must produce an API-visible finding"

        findings_list = router.handle(
            Request(method="GET", path="/api/v1/detections/credential-compromise/findings")
        )
        assert findings_list.status == 200
        assert findings_list.body["count"] >= 1

        explanation = router.handle(
            Request(method="GET", path=f"/api/v1/findings/{finding_id}/explanation")
        )
        assert explanation.status == 200
        assert explanation.body["explanation"]["top_contributors"]

        timeline = router.handle(
            Request(method="GET", path=f"/api/v1/identities/{benign[0].identity_key}/timeline")
        )
        assert timeline.status == 200 and timeline.body["finding_count"] >= 1

        behavior = router.handle(
            Request(method="GET", path=f"/api/v1/identities/{benign[0].identity_key}/behavior")
        )
        assert behavior.status == 200
        assert behavior.body["baseline_quality"] in ("EXCELLENT", "GOOD", "LIMITED", "COLD_START")

        # Evidence preserved: the finding carries the full ARDE bundle.
        store_finding = router.app.store.get(finding_id)
        assert store_finding["arde"]["checks"]
        assert store_finding["signals"]

        # Safety: no destructive capability anywhere on the router.
        forbidden_paths = (
            ("/api/v1/users/disable", "POST"),
            ("/api/v1/credentials/revoke", "POST"),
            ("/api/v1/resources/delete", "DELETE"),
        )
        for path, method in forbidden_paths:
            response = router.handle(Request(method=method, path=path))
            assert response.status == 404

    def test_confidence_is_not_risk_rescaled(self, normalized):
        detector = CredentialCompromiseDetector(config=DetectorConfig())
        detector.learn([e for e in normalized if e.timestamp < T0 + timedelta(days=45)])
        results = [detector.detect(e) for e in normalized[-4:]]
        for result in results:
            if result.is_finding:
                assert result.confidence != pytest.approx(result.risk / 100.0, abs=1e-9)
