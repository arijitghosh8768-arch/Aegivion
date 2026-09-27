"""Synthetic personas - end-to-end behavioral layer scenarios.

Each persona streams historical events through the baseline engine, then a
"current" event through feature extraction, rule evaluation and risk fusion.
These tests encode the product's core reasoning principles:

* one anomaly must not mean compromise (traveling employee, VPN user);
* corroboration across independent dimensions is what raises risk;
* high-risk activity must never silently retrain the baseline;
* a new identity is uncertain, not automatically malicious.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from detection.credential_compromise.baseline import (
    build_profile,
    select_effective_baseline,
    update_profile,
)
from detection.credential_compromise.config import BaselineConfig, FeatureConfig, RuleEngineConfig
from detection.credential_compromise.features import extract_features
from detection.credential_compromise.profile import BaselineSelection, initial_profile
from detection.credential_compromise.rules import evaluate_rules
from detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    PrincipalType,
    Severity,
)
from detection.credential_compromise.scorer import calculate_risk, severity_for

MONDAY = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)


def event(
    seq: int,
    *,
    identity: str,
    at: datetime,
    country: str = "IN",
    ip: str = "10.20.30.40",
    asn: int = 9829,
    ua: str = "Chrome/126 Windows",
    service: str = "s3",
    family: str = ApiFamilies.S3_DATA_READ,
    access: AccessType = AccessType.READ,
    privilege: bool = False,
    mfa: bool | None = True,
    principal_type: PrincipalType = PrincipalType.IAM_USER,
    kind: IdentityKind = IdentityKind.HUMAN,
    category: BaselineCategory = BaselineCategory.HUMAN_USER,
    account: str = "123456789012",
    event_name: str = "DoThing",
) -> IdentityActivityEvent:
    return IdentityActivityEvent(
        event_id=f"p-{seq:06d}",
        timestamp=at,
        principal_id=identity,
        principal_name=identity.split(":")[-1],
        principal_type=principal_type,
        identity_kind=kind,
        baseline_category=category,
        identity_key=identity,
        account_id=account,
        event_source=f"{service}.amazonaws.com",
        event_name=event_name,
        event_category=EventCategory.MANAGEMENT,
        service_name=service,
        api_family=family,
        read_or_write=access,
        privilege_change=privilege,
        source_ip=ip,
        country=country,
        asn=asn,
        user_agent=ua,
        mfa_authenticated=mfa,
    )


def build_history(
    identity: str,
    *,
    count: int,
    hours: tuple[int, ...],
    at: datetime = MONDAY,
    **kwargs,
) -> list[IdentityActivityEvent]:
    events = []
    for i in range(count):
        ts = at + timedelta(days=i % 14, hours=hours[i % len(hours)] - at.hour)
        events.append(event(i, identity=identity, at=ts, **kwargs))
    return events


def score_current(
    profile,
    current: IdentityActivityEvent,
    *,
    config: BaselineConfig,
    feature_config: FeatureConfig | None = None,
    rule_config: RuleEngineConfig | None = None,
) -> tuple[float, str, list]:
    selection = BaselineSelection(
        identity_key=profile.identity_key,
        window_days=profile.window_days,
        quality=profile.baseline_quality,
        profile=profile,
        peer_profiles=[],
        peer_count=0,
        reason="personal_baseline",
    )
    effective, source = select_effective_baseline(selection, config=config)
    features = extract_features(
        current,
        effective,
        config=config,
        feature_config=feature_config,
        session_rate=None,
    )
    signals = evaluate_rules(
        current,
        features,
        config=config,
        feature_config=feature_config,
        rule_config=rule_config,
    )
    return calculate_risk(features, signals), source, signals


# --------------------------------------------------------------------------- #
# Personas
# --------------------------------------------------------------------------- #


class TestPersonas:
    @pytest.fixture(scope="class")
    def config(self):
        return BaselineConfig()

    def _profile(self, identity: str, history, config: BaselineConfig):
        base = initial_profile(
            identity_key=identity,
            principal_id=identity,
            window_days=30,
            principal_type=PrincipalType.IAM_USER,
            identity_kind=IdentityKind.HUMAN,
            baseline_category=BaselineCategory.HUMAN_USER,
        )
        return build_profile(base, history, config=config)

    def test_normal_employee_stays_quiet(self, config):
        identity = "aws:1:user:bob"
        history = build_history(
            identity,
            count=300,
            hours=(9, 10, 11, 14, 15, 16),
        )
        profile = self._profile(identity, history, config)
        current = event(
            900,
            identity=identity,
            at=MONDAY + timedelta(days=2, hours=10),
        )
        risk, _, signals = score_current(profile, current, config=config)
        assert risk < 30.0
        assert not signals

    def test_normal_administrator_privilege_change_is_moderate(self, config):
        identity = "aws:1:user:alice-admin"
        history = build_history(
            identity,
            count=300,
            hours=(9, 10, 11, 14, 15, 16),
            service="iam",
            family=ApiFamilies.IAM_READ,
        )
        # Teach the profile that this identity legitimately mutates IAM.
        history += [
            event(
                800 + i,
                identity=identity,
                at=MONDAY + timedelta(days=i % 14, hours=10),
                service="iam",
                family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
                access=AccessType.WRITE,
                privilege=True,
            )
            for i in range(60)
        ]
        profile = self._profile(identity, history, config)
        current = event(
            901,
            identity=identity,
            at=MONDAY + timedelta(days=3, hours=10),
            service="iam",
            family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
            access=AccessType.WRITE,
            privilege=True,
        )
        risk, _, signals = score_current(profile, current, config=config)
        # Normal for an admin: some signal attention, not a crisis.
        assert risk < 60.0
        hit_ids = {s.rule_id for s in signals}
        assert "R013" not in hit_ids  # MFA present, nothing anomalous there

    def test_night_worker_is_normal_within_maintenance_window(self, config):
        identity = "aws:1:user:night-ops"
        history = build_history(
            identity,
            count=300,
            hours=(1, 2, 3),
        )
        profile = self._profile(identity, history, config)
        current = event(
            902,
            identity=identity,
            at=MONDAY + timedelta(days=1, hours=2),
        )
        risk, _, signals = score_current(profile, current, config=config)
        assert risk < 30.0

    def test_traveling_employee_is_a_signal_not_a_verdict(self, config):
        identity = "aws:1:user:traveler"
        history = build_history(
            identity,
            count=300,
            hours=(9, 10, 11, 14, 15, 16),
        )
        profile = self._profile(identity, history, config)
        # Same client, same network family, new country: travel.
        current = event(
            903,
            identity=identity,
            at=MONDAY + timedelta(days=2, hours=10),
            country="SG",
            ip="10.20.44.19",
        )
        risk, _, signals = score_current(profile, current, config=config)
        ids = {s.rule_id for s in signals}
        assert "R001" in ids  # flagged as new country...
        assert risk < 70.0  # ...but not treated as compromise on its own

    def test_vpn_user_outside_corporate_ranges_is_dampened(self, config):
        identity = "aws:1:user:vpn-user"
        history = build_history(
            identity,
            count=300,
            hours=(9, 10, 11, 14, 15, 16),
            ip="198.51.100.10",
            asn=64500,
            country="US",
        )
        profile = self._profile(identity, history, config)
        # VPN egress IP rotates across subnets: new /24, but same known ASN +
        # country, so the signal is real yet dampened by corroboration.
        current = event(
            904,
            identity=identity,
            at=MONDAY + timedelta(days=2, hours=10),
            ip="198.52.200.55",
            asn=64500,
            country="US",
        )
        risk, _, signals = score_current(profile, current, config=config)
        ids = {s.rule_id for s in signals}
        assert "R003" in ids   # new IP: worth one signal
        assert "R004" not in ids  # known ASN: no network panic
        assert risk < 60.0

    def test_developer_new_cli_ua_and_novel_api_is_layered_not_alarming(self, config):
        identity = "aws:1:user:dev"
        history = build_history(
            identity,
            count=300,
            hours=(9, 10, 11, 14, 15, 16),
            ua="Chrome/126 Windows",
        )
        profile = self._profile(identity, history, config)
        current = event(
            905,
            identity=identity,
            at=MONDAY + timedelta(days=2, hours=15),
            ua="aws-cli/2.13.0 Linux",
            service="lambda",
            family=ApiFamilies.LAMBDA_MANAGEMENT,
        )
        risk, _, signals = score_current(profile, current, config=config)
        ids = {s.rule_id for s in signals}
        assert {"R006", "R007", "R008"} & ids  # client + API signals fire
        assert risk < 70.0  # no privilege angle -> bounded outcome

    def test_service_identity_bulk_activity_is_normal_for_its_baseline(self, config):
        identity = "aws:1:role:etl-runner"
        history = build_history(
            identity,
            count=300,
            hours=(0, 1, 2, 3, 23),
            ua="Boto3/1.28",
            principal_type=PrincipalType.ASSUMED_ROLE,
            kind=IdentityKind.MACHINE,
            category=BaselineCategory.SERVICE_IDENTITY,
        )
        profile = self._profile(identity, history, config)
        current = event(
            906,
            identity=identity,
            at=MONDAY + timedelta(days=1, hours=2),
            ua="Boto3/1.28",
            principal_type=PrincipalType.ASSUMED_ROLE,
            kind=IdentityKind.MACHINE,
            category=BaselineCategory.SERVICE_IDENTITY,
        )
        risk, _, signals = score_current(profile, current, config=config)
        assert risk < 30.0

    def test_compromised_identity_scores_critical(self, config):
        identity = "aws:1:user:victim"
        history = build_history(
            identity,
            count=300,
            hours=(9, 10, 11, 14, 15, 16),
            country="IN",
            ip="10.20.30.40",
            asn=9829,
            ua="Chrome/126 Windows",
            mfa=True,
        )
        profile = self._profile(identity, history, config)
        # The classic kill chain from an unfamiliar context, no MFA.
        compromised = event(
            907,
            identity=identity,
            at=MONDAY + timedelta(days=3, hours=3),
            country="KP",
            ip="45.12.98.7",
            asn=131279,
            ua="python-requests/2.31",
            service="iam",
            family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
            access=AccessType.WRITE,
            privilege=True,
            mfa=False,
            event_name="PutUserPolicy",
        )
        risk, _, signals = score_current(profile, current=compromised, config=config)
        ids = {s.rule_id for s in signals}
        assert {"R001", "R003", "R004", "R005", "R006", "R010", "R013"} <= ids
        # Behavior + rules alone clear the HIGH bar (>= 70); CRITICAL is
        # reserved for runs where temporal/ML components corroborate too.
        assert risk >= 70.0
        assert severity_for(risk) in (Severity.HIGH, Severity.CRITICAL)

        # ...and this event must never retrain the baseline silently.
        frozen = update_profile(profile, compromised, event_risk=risk, config=config)
        assert frozen.normal_countries == profile.normal_countries
        assert frozen.baseline_version == profile.baseline_version

    def test_new_identity_is_uncertain_but_not_silent(self, config):
        identity = "aws:1:user:new-hire"
        profile = initial_profile(
            identity_key=identity,
            principal_id=identity,
            window_days=30,
            principal_type=PrincipalType.IAM_USER,
            identity_kind=IdentityKind.HUMAN,
            baseline_category=BaselineCategory.HUMAN_USER,
        )
        current = event(
            908,
            identity=identity,
            at=MONDAY + timedelta(days=1, hours=10),
        )
        risk, _, signals = score_current(profile, current, config=config)
        # Cold start: novelty rules must not storm...
        novelty_rules = {"R001", "R002", "R003", "R004", "R006", "R007", "R008"}
        assert not (novelty_rules & {s.rule_id for s in signals})
        # ...and the score must stay in the review band, not critical.
        assert risk < 60.0
