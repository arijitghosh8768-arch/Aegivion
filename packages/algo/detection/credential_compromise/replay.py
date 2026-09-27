"""Replay engine & evaluation utilities - **Part 2**.

Replay deterministically re-scores historical events through the full
pipeline (two passes: learn -> score) so temporal features never see the
future. Evaluation compares three detector configurations *quantitatively*:

    A. rules only            (no baseline, no ML)
    B. rules + baseline      (behavioral statistics, no ML)
    C. rules + baseline + ML (adds the Isolation Forest)

Metrics: precision, recall, F1, false-positive rate, and detection latency
(events observed before the first true-positive finding). ML is only claimed
to help when configuration C measurably beats B on these metrics; otherwise
the report says so plainly.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, Sequence

from detection.credential_compromise.anomaly import (
    IsolationForest,
    build_feature_vector,
)
from detection.credential_compromise.config import DetectorConfig
from detection.credential_compromise.detector import (
    CredentialCompromiseDetector,
    DetectionMode,
)
from detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    PrincipalType,
)


# --------------------------------------------------------------------------- #
# Synthetic dataset (labels are SYNTHETIC - see the honesty notes)
# --------------------------------------------------------------------------- #


def synthetic_dataset(
    *,
    n_identities: int = 12,
    n_benign_per_identity: int = 200,
    attack_ratio: float = 0.02,
    seed: int = 2026,
) -> tuple[list[IdentityActivityEvent], list[int]]:
    """Generate a synthetic, labeled event stream for pipeline evaluation.

    Benign traffic follows stable per-identity habits (office hours, home
    country, corporate network, steady service mix). Attack traffic is an
    injected kill-chain: odd hour, new country/network/client, IAM mutation,
    no MFA, frequently in bursts.

    **The labels are synthetic.** They support pipeline verification and
    relative comparisons only; they do not validate real-world performance
    and no such claim is made anywhere in this module.
    """
    rng = random.Random(seed)
    events: list[IdentityActivityEvent] = []
    labels: list[int] = []
    start = datetime(2026, 3, 1, 0, 0, tzinfo=timezone.utc)
    countries = ["IN", "US", "DE"]
    seq = 0

    for identity_idx in range(n_identities):
        identity = f"aws:111122223333:user:synth-{identity_idx}"
        home_country = rng.choice(countries)
        home_hour = rng.choice([9, 10, 11, 14, 15, 16])
        home_ip = f"10.{identity_idx}.30.40"
        home_asn = 9829 + identity_idx
        home_services = rng.sample(["s3", "ec2", "lambda", "dynamodb"], 2)

        for i in range(n_benign_per_identity):
            day_offset = i // 2
            hour = home_hour + rng.choice([-1, 0, 1])
            ts = start + timedelta(days=day_offset, hours=hour % 24)
            service = rng.choice(home_services)
            events.append(
                IdentityActivityEvent(
                    event_id=f"syn-{seq:07d}",
                    timestamp=ts,
                    principal_id=identity,
                    principal_name=f"synth-{identity_idx}",
                    principal_type=PrincipalType.IAM_USER,
                    identity_kind=IdentityKind.HUMAN,
                    baseline_category=BaselineCategory.HUMAN_USER,
                    identity_key=identity,
                    account_id="111122223333",
                    event_source=f"{service}.amazonaws.com",
                    event_name="DescribeThing",
                    event_category=EventCategory.MANAGEMENT,
                    service_name=service,
                    api_family=ApiFamilies.S3_DATA_READ
                    if service == "s3"
                    else ApiFamilies.EC2_READ,
                    read_or_write=AccessType.READ,
                    privilege_change=False,
                    source_ip=home_ip,
                    country=home_country,
                    asn=home_asn,
                    user_agent="aws-cli/2.13.0",
                    mfa_authenticated=True,
                )
            )
            labels.append(0)
            seq += 1

        # Inject attack kill-chains deterministically. ``attack_ratio``
        # controls the share of identities that receive a kill-chain
        # (0.02 -> ~1/4 of identities in small synthetic sets), always at
        # least one so evaluation sets contain positive examples.
        n_attack_identities = max(1, int(n_identities * min(0.5, attack_ratio * 12.5)))
        if identity_idx < n_attack_identities:
            for attack_idx, (day, hour) in enumerate(
                [(n_benign_per_identity // 2 + 40, 3), (n_benign_per_identity // 2 + 80, 4)]
            ):
                ts = start + timedelta(days=day, hours=hour)
                burst_times = [ts + timedelta(minutes=m) for m in (0, 2, 4, 6)]
                for j, burst_ts in enumerate(burst_times):
                    events.append(
                        IdentityActivityEvent(
                            event_id=f"syn-{seq:07d}",
                            timestamp=burst_ts,
                            principal_id=identity,
                            principal_name=f"synth-{identity_idx}",
                            principal_type=PrincipalType.IAM_USER,
                            identity_kind=IdentityKind.HUMAN,
                            baseline_category=BaselineCategory.HUMAN_USER,
                            identity_key=identity,
                            account_id="111122223333",
                            event_source="iam.amazonaws.com",
                            event_name=["ConsoleLogin", "AssumeRole", "PutUserPolicy", "CreateAccessKey"][j],
                            event_category=EventCategory.MANAGEMENT,
                            service_name="iam",
                            api_family=ApiFamilies.IAM_PRIVILEGE_MUTATION,
                            read_or_write=AccessType.WRITE,
                            privilege_change=True,
                            source_ip="45.12.98.7",
                            country="KP",
                            asn=131279,
                            user_agent="python-requests/2.31",
                            mfa_authenticated=False,
                        )
                    )
                    labels.append(1)
                    seq += 1

    # Keep the stream globally sorted for causal replay.
    paired = sorted(zip(events, labels), key=lambda pair: pair[0].timestamp)
    return [event for event, _ in paired], [label for _, label in paired]


# --------------------------------------------------------------------------- #
# Time-based split (no leakage)
# --------------------------------------------------------------------------- #


def temporal_split(
    events: Sequence[IdentityActivityEvent],
    labels: Sequence[int],
    *,
    train_fraction: float = 0.7,
) -> tuple[list[tuple[IdentityActivityEvent, int]], list[tuple[IdentityActivityEvent, int]]]:
    """Chronological split; training ends before evaluation begins."""
    if len(events) != len(labels):
        raise ValueError("events and labels must be the same length")
    paired = sorted(zip(events, labels), key=lambda pair: pair[0].timestamp)
    cutoff = int(len(paired) * train_fraction)
    return paired[:cutoff], paired[cutoff:]


# --------------------------------------------------------------------------- #
# Three-configuration evaluation
# --------------------------------------------------------------------------- #


@dataclass
class Metrics:
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    detection_latency_events: Optional[int] = None

    @property
    def precision(self) -> Optional[float]:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 4) if denom else None

    @property
    def recall(self) -> Optional[float]:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 4) if denom else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if not p or not r:
            return None
        return round(2 * p * r / (p + r), 4)

    @property
    def false_positive_rate(self) -> Optional[float]:
        denom = self.false_positives + self.true_negatives
        return round(self.false_positives / denom, 4) if denom else None

    def as_dict(self) -> dict[str, object]:
        return {
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "detection_latency_events": self.detection_latency_events,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
        }


@dataclass
class ScenarioResult:
    name: str
    metrics: Metrics

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, **self.metrics.as_dict()}


def _score_stream(
    events: Sequence[IdentityActivityEvent],
    labels: Sequence[int],
    *,
    scorer: Callable[[IdentityActivityEvent], Optional[float]],
    threshold: float,
) -> Metrics:
    """Score a labeled stream; label predicted positive when score >= threshold."""
    metrics = Metrics()
    first_hit_seen = False
    for event, label in zip(events, labels):
        score = scorer(event)
        predicted = score is not None and score >= threshold
        if predicted and label == 1:
            metrics.true_positives += 1
            if not first_hit_seen:
                metrics.detection_latency_events = 0
                first_hit_seen = True
        elif predicted and label == 0:
            metrics.false_positives += 1
        elif not predicted and label == 1:
            metrics.false_negatives += 1
            if not first_hit_seen:
                metrics.detection_latency_events = (
                    metrics.detection_latency_events or 0
                ) + 1
        else:
            metrics.true_negatives += 1
    return metrics


def compare_configurations(
    *,
    config: DetectorConfig,
    train: Sequence[tuple[IdentityActivityEvent, int]],
    test: Sequence[tuple[IdentityActivityEvent, int]],
    finding_threshold: float = 70.0,
) -> dict[str, ScenarioResult]:
    """Replay one labeled stream through the three detector configurations.

    A. rules only            - per-event intrinsic rules (R010/R012/R013)
    B. rules + baseline      - adds personal behavioral baselines
    C. rules + baseline + ML - adds the Isolation Forest trained on train
    """
    test_events = [event for event, _ in test]
    test_labels = [label for _, label in test]

    # ---- Configuration A: rules only ------------------------------------ #
    detector_a = CredentialCompromiseDetector(
        config=config, finding_threshold=finding_threshold
    )
    results_a = detector_a.replay(test_events)
    scores_a = [
        float(r.risk) if r.is_finding else 0.0 for r in results_a
    ]
    # Rules-only mode: use only event-intrinsic rule severities (score from
    # signals that do not depend on a baseline).
    def scorer_a(event: IdentityActivityEvent) -> Optional[float]:
        result = next(r for r in results_a if r.event_id == event.event_id)
        intrinsic = [
            s for s in result.signals if s.rule_id in ("R010", "R012", "R013")
        ]
        if not intrinsic:
            return None
        severities = {s.severity.upper() for s in intrinsic}
        if "CRITICAL" in severities:
            return 90.0
        if "HIGH" in severities:
            return 80.0
        return 60.0

    metrics_a = _score_stream(test_events, test_labels, scorer=scorer_a, threshold=finding_threshold)

    # ---- Configuration B: rules + baseline ------------------------------- #
    detector_b = CredentialCompromiseDetector(
        config=config, finding_threshold=finding_threshold
    )
    train_benign = [event for event, label in train if label == 0]
    by_identity: dict[str, list[IdentityActivityEvent]] = {}
    for event in train_benign:
        by_identity.setdefault(event.identity_key or event.principal_id, []).append(event)
    for identity, events in by_identity.items():
        detector_b.learn(events)
    results_b = detector_b.replay(test_events)

    def scorer_b(event: IdentityActivityEvent) -> Optional[float]:
        result = next(r for r in results_b if r.event_id == event.event_id)
        return float(result.risk) if result.is_finding else None

    metrics_b = _score_stream(test_events, test_labels, scorer=scorer_b, threshold=finding_threshold)

    # ---- Configuration C: rules + baseline + ML -------------------------- #
    detector_c = CredentialCompromiseDetector(
        config=config, finding_threshold=finding_threshold
    )
    for identity, events in by_identity.items():
        detector_c.learn(events)

    # Train the forest on benign training rows (unsupervised: labels unused).
    forest = IsolationForest(config=config.anomaly)
    benign_rows: list[tuple[float, ...]] = []
    from detection.credential_compromise.features import extract_features
    from detection.credential_compromise.temporal import (
        TemporalTracker,
        burst_score,
    )

    tracker = TemporalTracker()
    for event in train_benign:
        identity = event.identity_key or event.principal_id
        windows = tracker.window_slices(identity, at=event.timestamp)
        burst = burst_score(windows.get(5), windows.get(60))
        features = extract_features(
            event, detector_c._profiles.get((identity, config.baseline.primary_window_days)),
            config=config.baseline, feature_config=config.features,
        )
        vector = build_feature_vector(
            event, features, windows=windows, burst=burst, config=config.scoring
        )
        benign_rows.append(vector.values)
        tracker.observe(event)
    forest.fit(benign_rows)
    detector_c.anomaly_model = forest

    results_c = detector_c.replay(test_events)

    def scorer_c(event: IdentityActivityEvent) -> Optional[float]:
        result = next(r for r in results_c if r.event_id == event.event_id)
        return float(result.risk) if result.is_finding else None

    metrics_c = _score_stream(test_events, test_labels, scorer=scorer_c, threshold=finding_threshold)

    return {
        "A: rules only": ScenarioResult("A: rules only", metrics_a),
        "B: rules + baseline": ScenarioResult("B: rules + baseline", metrics_b),
        "C: rules + baseline + ML": ScenarioResult("C: rules + baseline + ML", metrics_c),
    }


def format_comparison_report(results: dict[str, ScenarioResult]) -> str:
    """Render the quantitative three-way comparison. Adds no claims."""
    header = (
        f"{'configuration':28s} {'precision':>9s} {'recall':>9s} {'f1':>9s} "
        f"{'FPR':>9s} {'latency(ev)':>11s}"
    )
    lines = [header, "-" * len(header)]

    def fmt(value: Optional[float]) -> str:
        return f"{value:.4f}" if value is not None else "-"

    for name, scenario in results.items():
        m = scenario.metrics
        lines.append(
            f"{name:28s} {fmt(m.precision):>9s} {fmt(m.recall):>9s} "
            f"{fmt(m.f1):>9s} {fmt(m.false_positive_rate):>9s} "
            f"{str(m.detection_latency_events if m.detection_latency_events is not None else '-'):>11s}"
        )
    lines.append("-" * len(header))
    lines.append(
        "Note: labels on the synthetic dataset are SYNTHETIC. Metrics support "
        "relative configuration comparison only, not real-world validation."
    )
    return "\n".join(lines)


__all__ = [
    "Metrics",
    "ScenarioResult",
    "compare_configurations",
    "format_comparison_report",
    "synthetic_dataset",
    "temporal_split",
]
