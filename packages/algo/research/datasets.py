"""Controlled evaluation datasets - **Part 4 (research)**.

Four scenario classes, exactly as the research brief demands. Compromise is
simulated as credential misuse only - no ransomware, exfiltration or
destructive activity is ever generated:

* ``NORMAL``             - steady habit-bound benign traffic,
* ``SINGLE_ANOMALY``     - exactly one deviant dimension per event (travel,
  VPN egress, new device, unusual hour), each explainable and benign,
* ``MULTI_SIGNAL``       - several weakly deviant dimensions that co-occur
  but stay non-privileged (the "corroboration without compromise" class that
  separates good detectors from noisy ones),
* ``SIMULATED_COMPROMISE`` - the credential-misuse kill chain: new country +
  new ASN + new client + unusual hour + unusual API sequence +
  privilege-modification APIs, performed without MFA.

Labels are **synthetic** and every artifact generated from them says so.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from algo.detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    PrincipalType,
)

SCENARIO_NORMAL = "NORMAL"
SCENARIO_SINGLE = "SINGLE_ANOMALY"
SCENARIO_MULTI = "MULTI_SIGNAL_ANOMALY"
SCENARIO_COMPROMISE = "SIMULATED_CREDENTIAL_COMPROMISE"

START = datetime(2026, 3, 1, 0, 0, tzinfo=timezone.utc)

#: Countries, ASNs and clients used for benign diversity.
BENIGN_COUNTRIES = ("IN", "US", "DE")
VPN_ASN = 64500


@dataclass
class Scenario:
    """One labeled evaluation stream for a single identity."""

    name: str
    identity_key: str
    events: list[IdentityActivityEvent] = field(default_factory=list)
    labels: list[int] = field(default_factory=list)   # 1 = compromise
    scenario: str = SCENARIO_NORMAL
    notes: str = ""

    def __len__(self) -> int:
        return len(self.events)


def _event(
    seq: int,
    *,
    identity: str,
    name_hint: str,
    at: datetime,
    country: str,
    ip: str,
    asn: int,
    ua: str,
    service: str,
    family: str,
    access: AccessType,
    privilege: bool,
    mfa: Optional[bool],
    event_name: str,
) -> IdentityActivityEvent:
    return IdentityActivityEvent(
        event_id=f"{name_hint}-{seq:07d}",
        timestamp=at,
        ingest_time=at,
        principal_id=identity,
        principal_name=identity.rsplit(":", 1)[-1],
        principal_type=PrincipalType.IAM_USER,
        identity_kind=IdentityKind.HUMAN,
        baseline_category=BaselineCategory.HUMAN_USER,
        identity_key=identity,
        account_id="313131313131",
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


def _normal_event(seq: int, identity: str, persona: dict, rng: random.Random) -> IdentityActivityEvent:
    day = seq // 2
    hour = (persona["home_hour"] + rng.choice((-1, 0, 1))) % 24
    service, family = persona["services"][seq % len(persona["services"])]
    return _event(
        seq,
        identity=identity,
        name_hint="norm",
        at=START + timedelta(days=day, hours=hour, minutes=rng.randrange(60)),
        country=persona["home_country"],
        ip=persona["home_ip"],
        asn=persona["home_asn"],
        ua=persona["home_ua"],
        service=service,
        family=family,
        access=AccessType.READ,
        privilege=False,
        mfa=True,
        event_name="DescribeThing",
    )


def normal_scenario(identity: str, persona: dict, n: int, rng: random.Random) -> Scenario:
    return Scenario(
        name="normal",
        identity_key=identity,
        events=[_normal_event(i, identity, persona, rng) for i in range(n)],
        labels=[0] * n,
        scenario=SCENARIO_NORMAL,
        notes="habit-bound benign traffic; zero positive labels",
    )


def single_anomaly_scenario(
    identity: str, persona: dict, n: int, rng: random.Random
) -> Scenario:
    """Every anomaly is a *single* deviant dimension and benign in nature."""
    events: list[IdentityActivityEvent] = []
    labels: list[int] = []
    for i in range(n):
        kind = i % 4
        if kind == 0:
            # Travel: new country, but same client / hour / service pattern.
            events.append(_event(
                i, identity=identity, name_hint="trv",
                at=START + timedelta(days=i // 2, hours=persona["home_hour"]),
                country=rng.choice([c for c in BENIGN_COUNTRIES if c != persona["home_country"]]),
                ip=persona["home_ip"], asn=persona["home_asn"],
                ua=persona["home_ua"], service="s3", family=ApiFamilies.S3_DATA_READ,
                access=AccessType.READ, privilege=False, mfa=True,
                event_name="GetObject",
            ))
        elif kind == 1:
            # Corporate VPN egress rotates /24s but keeps known ASN + country.
            events.append(_event(
                i, identity=identity, name_hint="vpn",
                at=START + timedelta(days=i // 2, hours=persona["home_hour"]),
                country=persona["home_country"], ip=f"198.52.201.{rng.randrange(2, 250)}",
                asn=VPN_ASN, ua=persona["home_ua"], service="s3",
                family=ApiFamilies.S3_DATA_READ, access=AccessType.READ,
                privilege=False, mfa=True, event_name="GetObject",
            ))
        elif kind == 2:
            # New workstation: new client, everything else normal.
            events.append(_event(
                i, identity=identity, name_hint="dev",
                at=START + timedelta(days=i // 2, hours=persona["home_hour"]),
                country=persona["home_country"], ip=persona["home_ip"],
                asn=persona["home_asn"], ua="Firefox/127 Ubuntu",
                service="s3", family=ApiFamilies.S3_DATA_READ,
                access=AccessType.READ, privilege=False, mfa=True,
                event_name="GetObject",
            ))
        else:
            # Late-evening work session: unusual hour, everything else normal.
            events.append(_event(
                i, identity=identity, name_hint="hour",
                at=START + timedelta(days=i // 2, hours=21),
                country=persona["home_country"], ip=persona["home_ip"],
                asn=persona["home_asn"], ua=persona["home_ua"],
                service="s3", family=ApiFamilies.S3_DATA_READ,
                access=AccessType.READ, privilege=False, mfa=True,
                event_name="GetObject",
            ))
        labels.append(0)
    return Scenario(
        name="single-anomaly",
        identity_key=identity,
        events=events,
        labels=labels,
        scenario=SCENARIO_SINGLE,
        notes="one deviant dimension per event; all benign (labels 0)",
    )


def multi_signal_scenario(
    identity: str, persona: dict, n: int, rng: random.Random
) -> Scenario:
    """Several weak anomalies co-occur; still not compromise (labels 0).

    Deliberately *non-privileged and non-geo*: new client + unusual hour +
    new API. The class exists to verify the detector elevates risk without
    declaring compromise - so it must stay separable from the attack class,
    whose distinguishing signal is privilege mutation without MFA.
    """
    events: list[IdentityActivityEvent] = []
    labels: list[int] = []
    for i in range(n):
        events.append(_event(
            i, identity=identity, name_hint="multi",
            at=START + timedelta(days=i // 2, hours=20),
            country=persona["home_country"],
            ip=persona["home_ip"],
            asn=persona["home_asn"],
            ua="Firefox/127 Ubuntu",
            service="dynamodb", family=ApiFamilies.DEFAULT,
            access=AccessType.READ, privilege=False, mfa=True,
            event_name="DescribeThing",
        ))
        labels.append(0)
    return Scenario(
        name="multi-signal",
        identity_key=identity,
        events=events,
        labels=labels,
        scenario=SCENARIO_MULTI,
        notes="corroborating weak anomalies, non-privileged; labels 0",
    )


def compromise_scenario(
    identity: str, persona: dict, n_benign: int, n_attack: int, rng: random.Random
) -> Scenario:
    """Benign history with two credential-misuse kill chains (labels 1).

    Two waves are injected so that a chronological train/val/test split puts
    one wave in *validation* (for threshold tuning) and one in *test*. With
    ~2 benign events/day, ``wave1_day = 0.42 * n_benign`` lands mid-stream
    and ``wave2_day = 0.88 * n_benign`` lands in the latest segment.

    Credential misuse only: recon -> role assumption -> policy mutation ->
    new key. No data destruction, no exfiltration volume, no ransomware.
    """
    events = [_normal_event(i, identity, persona, rng) for i in range(n_benign)]
    labels = [0] * n_benign
    seq = n_benign
    chain = (
        ("iam", ApiFamilies.IAM_READ, "read", False, "GetAccountAuthorizationDetails"),
        ("sts", ApiFamilies.STS_SESSION, "read", False, "AssumeRole"),
        ("iam", ApiFamilies.IAM_PRIVILEGE_MUTATION, "write", True, "PutUserPolicy"),
        ("iam", ApiFamilies.CREDENTIAL_MANAGEMENT, "write", True, "CreateAccessKey"),
    )
    for wave_day in (int(n_benign * 0.42), int(n_benign * 0.88)):
        for j in range(n_attack):
            step = chain[j % len(chain)]
            events.append(_event(
                seq,
                identity=identity,
                name_hint="cmp",
                at=START + timedelta(days=wave_day, hours=3, minutes=4 * j),
                country="KP",
                ip="45.12.98.7",
                asn=131279,
                ua="python-requests/2.31",
                service=step[0],
                family=step[1],
                access=AccessType(step[2]),
                privilege=step[3],
                mfa=False,
                event_name=step[4],
            ))
            labels.append(1)
            seq += 1
    return Scenario(
        name="simulated-compromise",
        identity_key=identity,
        events=events,
        labels=labels,
        scenario=SCENARIO_COMPROMISE,
        notes="credential-misuse kill chain only; no destructive activity simulated",
    )


def build_persona(rng: random.Random, index: int) -> dict:
    """One identity's benign habits (varied for cross-identity validation)."""
    return {
        "home_country": BENIGN_COUNTRIES[index % len(BENIGN_COUNTRIES)],
        "home_hour": (8 + (index * 2) % 9),          # 08:00 .. 16:00 starts
        "home_ip": f"10.{index}.30.40",
        "home_asn": 9829 + index,
        "home_ua": rng.choice(("Chrome/126 Windows", "Edge/126 Windows", "Safari/17 macOS")),
        "services": rng.sample(
            (
                ("s3", ApiFamilies.S3_DATA_READ),
                ("ec2", ApiFamilies.EC2_READ),
                ("iam", ApiFamilies.IAM_READ),
                ("lambda", ApiFamilies.LAMBDA_MANAGEMENT),
            ),
            2,
        ),
    }


def build_research_dataset(
    *,
    n_identities: int = 10,
    n_benign: int = 200,
    n_single: int = 40,
    n_multi: int = 40,
    n_attack: int = 8,
    compromise_every: int = 2,
    seed: int = 2026,
) -> list[Scenario]:
    """The full controlled dataset: four scenario classes per identity mix."""
    rng = random.Random(seed)
    scenarios: list[Scenario] = []
    for index in range(n_identities):
        identity = f"aws:313131313131:human_user:arn:aws:iam::313131313131:user/research-{index}"
        persona = build_persona(rng, index)
        scenarios.append(normal_scenario(identity, persona, n_benign, rng))
        scenarios.append(single_anomaly_scenario(identity, persona, n_single, rng))
        scenarios.append(multi_signal_scenario(identity, persona, n_multi, rng))
        if index % compromise_every == 0:
            scenarios.append(
                compromise_scenario(identity, persona, n_benign, n_attack, rng)
            )
    return scenarios


__all__ = [
    "Scenario",
    "SCENARIO_NORMAL",
    "SCENARIO_SINGLE",
    "SCENARIO_MULTI",
    "SCENARIO_COMPROMISE",
    "build_persona",
    "build_research_dataset",
]
