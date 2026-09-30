"""API integration tests (framework-free router)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from algo.api.server import DetectionApp, Request, Router
from algo.detection.credential_compromise.config import DetectorConfig
from algo.detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    PrincipalType,
)

T0 = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
IDENTITY = "aws:111122223333:human_user:api-user"


def event(seq: int, at: datetime, **overrides) -> IdentityActivityEvent:
    payload = dict(
        event_id=f"api-{seq:05d}",
        timestamp=at,
        ingest_time=at,
        principal_id=IDENTITY,
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
        identity_key=IDENTITY,
        account_id="111122223333",
        event_source="s3.amazonaws.com",
        event_name="GetObject",
        event_category=EventCategory.DATA,
        service_name="s3",
        api_family=ApiFamilies.S3_DATA_READ,
        read_or_write=AccessType.READ,
        privilege_change=False,
        source_ip="10.20.30.40",
        country="IN",
        asn=9829,
        user_agent="aws-cli/2.13.0",
        mfa_authenticated=True,
    )
    payload.update(overrides)
    return IdentityActivityEvent(**payload)


@pytest.fixture()
def router():
    router = Router(DetectionApp(config=DetectorConfig()))
    router.app.detector.learn(
        [event(i, T0 + timedelta(days=i % 14, hours=10)) for i in range(300)]
    )
    return router


ANALYZE = "/api/v1/detections/credential-compromise/analyze"
FINDINGS = "/api/v1/detections/credential-compromise/findings"


def _attack_event(seq: int = 901) -> IdentityActivityEvent:
    return event(
        seq,
        T0 + timedelta(days=20, hours=3),
        country="KP",
        source_ip="45.12.98.7",
        asn=131279,
        user_agent="python-requests/2.31",
        event_source="iam.amazonaws.com",
        event_name="PutUserPolicy",
        event_category=EventCategory.MANAGEMENT,
        service_name="iam",
        api_family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
        read_or_write=AccessType.WRITE,
        privilege_change=True,
        mfa_authenticated=False,
    )


class TestAnalyzeEndpoint:
    def test_analyze_returns_separate_risk_confidence_validation(self, router):
        response = router.handle(Request("POST", ANALYZE, body=_attack_event().model_dump(mode="json")))
        assert response.status == 200
        body = response.body
        assert body["is_finding"]
        assert 0 <= body["risk_score"] <= 100
        assert 0 <= body["confidence"] <= 1
        assert body["arde_status"] in ("PASSED", "PASSED_WITH_WARNINGS", "REVIEW_REQUIRED", "REJECTED")
        # The four concepts are distinct fields, not one blurred number.
        assert set(body["distinguishes"]) == {"anomaly", "risk", "confidence", "validated_finding"}

    def test_analyze_rejects_malformed_body(self, router):
        response = router.handle(Request("POST", ANALYZE, body={"garbage": True}))
        assert response.status == 400
        assert "error" in response.body

    def test_analyze_rejects_empty_body(self, router):
        response = router.handle(Request("POST", ANALYZE, body=None))
        assert response.status == 400

    def test_quiet_event_is_not_a_finding(self, router):
        quiet = event(950, T0 + timedelta(days=21, hours=10))
        response = router.handle(Request("POST", ANALYZE, body=quiet.model_dump(mode="json")))
        assert response.status == 200
        assert response.body["is_finding"] is False


class TestReadEndpoints:
    def test_findings_listing(self, router):
        router.handle(Request("POST", ANALYZE, body=_attack_event().model_dump(mode="json")))
        response = router.handle(Request("GET", FINDINGS))
        assert response.status == 200
        assert response.body["count"] >= 1

    def test_behavior_endpoint(self, router):
        response = router.handle(Request("GET", f"/api/v1/identities/{IDENTITY}/behavior"))
        assert response.status == 200
        assert response.body["baseline_quality"] in ("EXCELLENT", "GOOD", "LIMITED", "COLD_START")
        assert "normal_hours" in response.body

    def test_behavior_unknown_identity_is_404(self, router):
        response = router.handle(Request("GET", "/api/v1/identities/aws:1:user:ghost/behavior"))
        assert response.status == 404

    def test_timeline_endpoint(self, router):
        router.handle(Request("POST", ANALYZE, body=_attack_event().model_dump(mode="json")))
        response = router.handle(Request("GET", f"/api/v1/identities/{IDENTITY}/timeline"))
        assert response.status == 200
        assert response.body["finding_count"] >= 1

    def test_explanation_endpoint(self, router):
        analyze = router.handle(Request("POST", ANALYZE, body=_attack_event().model_dump(mode="json")))
        finding_id = analyze.body["finding_id"]
        response = router.handle(Request("GET", f"/api/v1/findings/{finding_id}/explanation"))
        assert response.status == 200
        assert response.body["explanation"]["top_contributors"]
        assert "recommended_next_steps" in response.body

    def test_unknown_finding_is_404(self, router):
        response = router.handle(Request("GET", "/api/v1/findings/NOPE/explanation"))
        assert response.status == 404

    def test_unknown_route_is_404(self, router):
        response = router.handle(Request("GET", "/api/v1/does-not-exist"))
        assert response.status == 404
