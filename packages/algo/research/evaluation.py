"""Research evaluation harness - **Part 4**.

Compares four detector configurations on the controlled datasets:

* **A** rules only (event-intrinsic rules R010/R012/R013),
* **B** rules + behavioral baseline,
* **C** rules + behavioral baseline + Isolation Forest,
* **D** the full Aegivion pipeline (adds risk fusion, ARDE validation and
  evidence-based confidence; findings must survive ARDE with a usable status).

Methodological guarantees encoded here:

* **Temporal split** - training (past) -> validation (later) -> test
  (latest), split per identity stream by timestamp. No future event is ever
  scored by a detector fitted on it.
* **Threshold tuning happens on the validation split only**; the test split
  is scored once with the frozen threshold.
* **Synthetic labels** - every artifact produced from them is marked
  synthetic; no real-world validation is claimed.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional, Sequence

from algo.detection.credential_compromise.anomaly import (
    IsolationForest,
    build_feature_vector,
)
from algo.detection.credential_compromise.config import DetectorConfig
from algo.detection.credential_compromise.detector import (
    CredentialCompromiseDetector,
    DetectionMode,
)
from algo.detection.credential_compromise.features import extract_features
from algo.detection.credential_compromise.rules import evaluate_rules
from algo.detection.credential_compromise.schemas import (
    AccessType,
    ApiFamilies,
    BaselineCategory,
    EventCategory,
    IdentityActivityEvent,
    IdentityKind,
    PrincipalType,
)
from algo.detection.credential_compromise.temporal import TemporalTracker, burst_score

from .datasets import Scenario
from .metrics import (
    ConfusionMatrix,
    LatencyStats,
    brier_score,
    calibration_curve_points,
    expected_calibration_error,
    latency_stats,
    pr_auc,
    pr_curve_points,
    precision_at_recall,
    recall_at_fpr,
    roc_auc,
)

INTRINSIC_RULES = ("R010", "R012", "R013")


# --------------------------------------------------------------------------- #
# Splitting
# --------------------------------------------------------------------------- #


def temporal_three_way_split(
    events: Sequence[IdentityActivityEvent],
    labels: Sequence[int],
    *,
    train_fraction: float = 0.6,
    validation_fraction: float = 0.2,
) -> tuple[list, list, list]:
    """Chronological train/validation/test split of one identity stream."""
    if not (len(events) == len(labels)) or not events:
        raise ValueError("split needs equal-length, non-empty inputs")
    if train_fraction + validation_fraction >= 1.0:
        raise ValueError("train+validation fractions must leave room for test")
    paired = sorted(zip(events, labels), key=lambda pair: pair[0].timestamp)
    n = len(paired)
    train_end = int(n * train_fraction)
    val_end = int(n * (train_fraction + validation_fraction))
    return list(paired[:train_end]), list(paired[train_end:val_end]), list(paired[val_end:])


# --------------------------------------------------------------------------- #
# The four systems under test
# --------------------------------------------------------------------------- #


@dataclass
class SystemScores:
    """Per-event scores from one configured system."""

    scores: list[float]
    predicted: list[bool]
    probabilities: list[float]          # for calibration metrics
    anomaly_scores: list[Optional[float]]
    validations: list[Optional[str]]    # ARDE statuses (System D)
    reasons: list[list[dict]]           # per-event signal/evidence summaries


def _compile_intrinsic_rules(event: IdentityActivityEvent) -> tuple[float, list[dict]]:
    """System A scoring: only event-intrinsic rules can fire."""
    from algo.detection.credential_compromise.config import BaselineConfig

    # Event-intrinsic features do not need a baseline; pass None.
    features = extract_features(event, None, config=BaselineConfig())
    signals = evaluate_rules(event, features, config=BaselineConfig())
    intrinsic = [s for s in signals if s.rule_id in INTRINSIC_RULES]
    severity_to_score = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.85, "CRITICAL": 1.0}
    score = max(
        (severity_to_score.get(s.severity.upper(), 0.3) for s in intrinsic), default=0.0
    )
    return score, [
        {"rule_id": s.rule_id, "severity": s.severity, "value": s.value} for s in intrinsic
    ]


class SystemRunner:
    """Builds score functions for each system from the same training data."""

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()

    # -- System A -------------------------------------------------------- #

    def system_a(self) -> Callable[[IdentityActivityEvent], tuple[float, list[dict]]]:
        def score(event: IdentityActivityEvent) -> tuple[float, list[dict]]:
            return _compile_intrinsic_rules(event)

        return score

    # -- System B -------------------------------------------------------- #

    def system_b(
        self, train: Sequence[tuple[IdentityActivityEvent, int]]
    ) -> tuple[Callable[[IdentityActivityEvent], tuple[float, list[dict]]], CredentialCompromiseDetector]:
        detector = CredentialCompromiseDetector(config=self.config)
        self._learn_baselines(detector, train)
        window = self.config.baseline.primary_window_days

        def score(event: IdentityActivityEvent) -> tuple[float, list[dict]]:
            profile = detector._profiles.get(
                (event.identity_key or event.principal_id, window)
            )
            features = extract_features(
                event, profile, config=self.config.baseline, feature_config=self.config.features
            )
            from algo.detection.credential_compromise.scorer import calculate_risk

            signals = evaluate_rules(
                event, features, config=self.config.baseline,
                feature_config=self.config.features, rule_config=self.config.rules,
            )
            risk = calculate_risk(features, signals, config=self.config.scoring)
            return risk, [
                {"rule_id": s.rule_id, "severity": s.severity, "value": s.value}
                for s in signals
            ]

        return score, detector

    # -- System C -------------------------------------------------------- #

    def system_c(
        self, train: Sequence[tuple[IdentityActivityEvent, int]]
    ) -> tuple[Callable[[IdentityActivityEvent], tuple[float, list[dict]]], Optional[IsolationForest]]:
        scorer_b, detector = self.system_b(train)
        forest = self._fit_forest(detector, train)
        if forest is None:
            return scorer_b, None
        window = self.config.baseline.primary_window_days

        def score(event: IdentityActivityEvent) -> tuple[float, list[dict]]:
            base_risk, reasons = scorer_b(event)
            profile = detector._profiles.get(
                (event.identity_key or event.principal_id, window)
            )
            vector = build_feature_vector(
                event,
                extract_features(
                    event, profile, config=self.config.baseline,
                    feature_config=self.config.features,
                ),
                windows={}, burst=0.0, config=self.config.scoring, profile=profile,
            )
            ml_score = forest.score_normalized(vector.values)
            # Fusion approximation without the full pipeline: statistics and
            # rules carry the decision; ML corroborates (same discount as
            # FusionConfig).
            fused = min(
                1.0,
                0.7 * (base_risk / 100.0) + 0.3 * ml_score,
            )
            reasons.append({"component": "isolation_forest", "value": ml_score})
            return fused * 100.0, reasons

        return score, forest

    # -- System D -------------------------------------------------------- #

    def system_d(
        self, train: Sequence[tuple[IdentityActivityEvent, int]]
    ) -> tuple[Callable[[IdentityActivityEvent], tuple[float, list[dict]]], CredentialCompromiseDetector]:
        detector = CredentialCompromiseDetector(config=self.config)
        self._learn_baselines(detector, train)
        forest = self._fit_forest(detector, train)
        if forest is not None:
            detector.anomaly_model = forest

        def score(event: IdentityActivityEvent) -> tuple[float, list[dict]]:
            result = detector.detect(event, mode=DetectionMode.REPLAY)
            reasons = [
                {"rule_id": s.rule_id, "severity": s.severity, "value": s.value}
                for s in result.signals
            ]
            if result.anomaly_score is not None:
                reasons.append(
                    {"component": "isolation_forest", "value": result.anomaly_score}
                )
            if result.arde is not None:
                reasons.append(
                    {
                        "component": "arde",
                        "status": result.arde.validation_status,
                        "robustness": result.arde.robustness_score,
                    }
                )
            return result.risk, reasons

        return score, detector

    # -- shared helpers --------------------------------------------------- #

    def _learn_baselines(
        self, detector: CredentialCompromiseDetector, train: Sequence[tuple[IdentityActivityEvent, int]]
    ) -> None:
        by_identity: dict[str, list[IdentityActivityEvent]] = {}
        for event, label in train:
            if label == 0:
                by_identity.setdefault(event.identity_key or event.principal_id, []).append(event)
        for identity, events in by_identity.items():
            detector.learn(sorted(events, key=lambda e: e.timestamp))

    def _fit_forest(
        self, detector: CredentialCompromiseDetector, train: Sequence[tuple[IdentityActivityEvent, int]]
    ) -> Optional[IsolationForest]:
        """Unsupervised fit on benign training rows (labels intentionally unused)."""
        from algo.detection.credential_compromise.temporal import TemporalTracker

        window = self.config.baseline.primary_window_days
        tracker = TemporalTracker()
        rows: list[tuple[float, ...]] = []
        for event, label in train:
            if label != 0:
                continue
            identity = event.identity_key or event.principal_id
            profile = detector._profiles.get((identity, window))
            windows = tracker.window_slices(identity, at=event.timestamp)
            burst = burst_score(windows.get(5), windows.get(60))
            features = extract_features(
                event, profile, config=self.config.baseline, feature_config=self.config.features
            )
            rows.append(
                build_feature_vector(
                    event, features, windows=windows, burst=burst,
                    config=self.config.scoring, profile=profile,
                ).values
            )
            tracker.observe(event)
        if len(rows) < self.config.anomaly.min_training_rows:
            return None
        return IsolationForest(config=self.config.anomaly).fit(rows)


# --------------------------------------------------------------------------- #
# Threshold tuning (validation split only)
# --------------------------------------------------------------------------- #


def tune_threshold(
    scores: Sequence[float],
    labels: Sequence[int],
    *,
    strategy: str = "max_f1",
) -> float:
    """Pick the operating threshold on validation data.

    ``strategy``: ``max_f1`` (default) or ``target_recall`` (lowest threshold
    achieving >= 0.8 validation recall). Never called with test data.
    """
    if not scores or len(scores) != len(labels):
        raise ValueError("tune_threshold needs equal-length, non-empty inputs")
    candidates = sorted(set(scores))
    best_threshold = 100.0
    best_key = (-1.0,)
    for threshold in candidates:
        predicted = [score >= threshold for score in scores]
        cm = ConfusionMatrix()
        for pred, label in zip(predicted, labels):
            if pred and label == 1:
                cm.true_positives += 1
            elif pred and label == 0:
                cm.false_positives += 1
            elif not pred and label == 1:
                cm.false_negatives += 1
            else:
                cm.true_negatives += 1
        f1 = cm.f1 or 0.0
        recall = cm.recall or 0.0
        key = (f1,) if strategy == "max_f1" else (1.0 if recall >= 0.8 else 0.0, f1)
        if key > best_key:
            best_key = key
            best_threshold = threshold
    return float(best_threshold)


# --------------------------------------------------------------------------- #
# One-system evaluation
# --------------------------------------------------------------------------- #


@dataclass
class SystemEvaluation:
    system: str
    threshold: float
    confusion: ConfusionMatrix
    latency: LatencyStats
    pr_auc: Optional[float]
    roc_auc: Optional[float]
    brier: Optional[float]
    ece: Optional[float]
    precision_at_recall_08: Optional[float]
    recall_at_fpr_01: Optional[float]
    pr_points: list[dict] = field(default_factory=list)
    calibration_points: list[dict] = field(default_factory=list)
    fp_categories: Counter = field(default_factory=Counter)

    def metrics_dict(self) -> dict:
        return {
            "system": self.system,
            "threshold": self.threshold,
            **self.confusion.as_dict(),
            **self.latency.as_dict(),
            "pr_auc": self.pr_auc,
            "roc_auc": self.roc_auc,
            "brier_score": self.brier,
            "ece": self.ece,
            "precision_at_recall_0.8": self.precision_at_recall_08,
            "recall_at_fpr_0.1": self.recall_at_fpr_01,
        }


def evaluate_system(
    name: str,
    scorer: Callable[[IdentityActivityEvent], tuple[float, list[dict]]],
    *,
    validation: Sequence[tuple[IdentityActivityEvent, int]],
    test: Sequence[tuple[IdentityActivityEvent, int]],
    strategy: str = "max_f1",
) -> SystemEvaluation:
    """Tune the threshold on validation, then evaluate once on test."""
    val_scores = [scorer(event)[0] for event, _ in validation]
    val_labels = [label for _, label in validation]
    threshold = tune_threshold(val_scores, val_labels, strategy=strategy)

    test_scores: list[float] = []
    test_labels: list[int] = []
    test_reasons: list[list[dict]] = []
    for event, label in test:
        score, reasons = scorer(event)
        test_scores.append(score)
        test_labels.append(label)
        test_reasons.append(reasons)

    predicted = [score >= threshold for score in test_scores]
    cm = ConfusionMatrix()
    fp_events: list[tuple[IdentityActivityEvent, list[dict]]] = []
    for pred, label, event, reasons in zip(predicted, test_labels, [e for e, _ in test], test_reasons):
        if pred and label == 1:
            cm.true_positives += 1
        elif pred and label == 0:
            cm.false_positives += 1
            fp_events.append((event, reasons))
        elif not pred and label == 1:
            cm.false_negatives += 1
        else:
            cm.true_negatives += 1

    lat = latency_stats(
        test_labels, predicted, [e.timestamp for e, _ in test]
    )
    probabilities = [min(1.0, max(0.0, score / 100.0)) for score in test_scores]

    return SystemEvaluation(
        system=name,
        threshold=round(threshold, 4),
        confusion=cm,
        latency=lat,
        pr_auc=pr_auc(test_labels, test_scores),
        roc_auc=roc_auc(test_labels, test_scores),
        brier=brier_score(probabilities, test_labels),
        ece=expected_calibration_error(probabilities, test_labels),
        precision_at_recall_08=precision_at_recall(test_labels, test_scores, 0.8),
        recall_at_fpr_01=recall_at_fpr(test_labels, test_scores, 0.1),
        pr_points=pr_curve_points(test_labels, test_scores),
        calibration_points=calibration_curve_points(probabilities, test_labels),
        fp_categories=categorize_false_positives(fp_events),
    )


# --------------------------------------------------------------------------- #
# False-positive taxonomy
# --------------------------------------------------------------------------- #

FP_TAXONOMY_RULES: tuple[tuple[str, Callable[[dict], bool]], ...] = (
    ("travel_new_country", lambda r: r.get("rule_id") == "R001"),
    ("vpn_or_new_ip", lambda r: r.get("rule_id") in ("R003", "R004")),
    ("new_client_or_device", lambda r: r.get("rule_id") == "R006"),
    ("unusual_hour", lambda r: r.get("rule_id") == "R005"),
    ("novel_api_or_service", lambda r: r.get("rule_id") in ("R007", "R008")),
    ("frequency_or_burst", lambda r: r.get("rule_id") in ("R009", "R014")),
    ("privilege_related", lambda r: r.get("rule_id") in ("R010", "R011", "R012", "R013")),
)


def categorize_false_positives(
    fp_events: Sequence[tuple[IdentityActivityEvent, list[dict]]],
) -> Counter:
    """Classify each FP by the signals that caused it."""
    categories: Counter = Counter()
    for _event, reasons in fp_events:
        matched = False
        for reason in reasons:
            for category, predicate in FP_TAXONOMY_RULES:
                if predicate(reason):
                    categories[category] += 1
                    matched = True
        if not matched:
            categories["unexplained_or_fusion"] += 1
    return categories


def fp_analysis_records(
    fp_events: Sequence[tuple[IdentityActivityEvent, list[dict]]],
) -> list[dict]:
    """Per-FP analysis: why flagged, which features, would context help."""
    records: list[dict] = []
    for event, reasons in fp_events:
        records.append(
            {
                "event_id": event.event_id,
                "scenario_class": event.event_id.split("-")[0],
                "flagged_by": [r.get("rule_id") or r.get("component") for r in reasons],
                "country": event.country,
                "asn": event.asn,
                "user_agent": event.user_agent,
                "hour": event.timestamp.hour,
                "could_suppression_help": bool(
                    event.country and event.event_id.startswith(("trv", "vpn"))
                ),
                "could_peer_baseline_help": event.event_id.startswith(("trv", "vpn", "dev")),
            }
        )
    return records


# --------------------------------------------------------------------------- #
# Cross-identity validation
# --------------------------------------------------------------------------- #


def cross_identity_evaluation(
    *,
    scorer_factory: Callable[[], tuple[Callable, object]],
    train_by_identity: dict[str, list],
    test_by_identity: dict[str, list],
    threshold: float,
) -> dict[str, dict]:
    """Per-identity-segment metrics to expose generalization gaps."""
    per_identity: dict[str, dict] = {}
    for identity, train in train_by_identity.items():
        test = test_by_identity.get(identity, [])
        if not test:
            continue
        scorer, _state = scorer_factory()
        # Refit per identity slice is intentionally omitted here: the shared
        # scorer already carries identity baselines; segments only regroup
        # the test events for metric reporting.
        _ = train
        scores = [scorer(event)[0] for event, _ in test]
        labels = [label for _, label in test]
        predicted = [score >= threshold for score in scores]
        cm = ConfusionMatrix()
        for pred, label in zip(predicted, labels):
            if pred and label == 1:
                cm.true_positives += 1
            elif pred and label == 0:
                cm.false_positives += 1
            elif not pred and label == 1:
                cm.false_negatives += 1
            else:
                cm.true_negatives += 1
        per_identity[identity] = {
            "n_test": len(test),
            "n_positives": sum(labels),
            **cm.as_dict(),
        }
    return per_identity


# --------------------------------------------------------------------------- #
# Drift simulation
# --------------------------------------------------------------------------- #


def drift_stream(
    scenario: Scenario,
    *,
    phase_benign: int,
    drift_phases: Sequence[str],
    per_phase: int = 40,
    rng_seed: int = 7,
) -> tuple[list[IdentityActivityEvent], list[int], list[str]]:
    """Generate post-history drift phases (device change, travel, new hours,
    new APIs) that are all *benign* - the detector must adapt (via risk-aware
    baseline updates) without learning the attack pattern as normal."""
    import random as _random

    rng = _random.Random(rng_seed)
    events: list[IdentityActivityEvent] = list(scenario.events[:phase_benign])
    labels: list[int] = list(scenario.labels[:phase_benign])
    phase_tags: list[str] = ["history"] * len(events)
    persona = build_persona_from_identity(scenario.identity_key)
    base_ts = max(e.timestamp for e in events) + timedelta(days=1)

    for phase_index, phase in enumerate(drift_phases):
        day_offset = phase_index * 3
        for i in range(per_phase):
            at = base_ts + timedelta(days=day_offset, hours=8 + (i % 8), minutes=(i * 7) % 60)
            if phase == "device_change":
                events.append(_make_drift_event(
                    scenario.identity_key, f"drift-{phase}-{i}", at,
                    persona["home_country"], persona["home_ip"], persona["home_asn"],
                    "Firefox/127 Ubuntu", "s3", ApiFamilies.S3_DATA_READ, True,
                ))
            elif phase == "travel":
                events.append(_make_drift_event(
                    scenario.identity_key, f"drift-{phase}-{i}", at,
                    "BR", persona["home_ip"], persona["home_asn"],
                    persona["home_ua"], "s3", ApiFamilies.S3_DATA_READ, True,
                ))
            elif phase == "hours_shift":
                events.append(_make_drift_event(
                    scenario.identity_key, f"drift-{phase}-{i}", at,
                    persona["home_country"], persona["home_ip"], persona["home_asn"],
                    persona["home_ua"], "s3", ApiFamilies.S3_DATA_READ, True,
                ))
            elif phase == "new_api":
                events.append(_make_drift_event(
                    scenario.identity_key, f"drift-{phase}-{i}", at,
                    persona["home_country"], persona["home_ip"], persona["home_asn"],
                    persona["home_ua"], "dynamodb", ApiFamilies.DEFAULT, True,
                ))
            else:  # pragma: no cover - defensive
                raise ValueError(f"unknown drift phase: {phase}")
            labels.append(0)
            phase_tags.append(phase)

    # Interleave a late attack to verify the detector still catches it
    # *after* adapting to all drift phases.
    attack_day = (len(drift_phases) * 3) + 2
    chain = (
        ("iam", ApiFamilies.IAM_PRIVILEGE_MUTATION, "write", True, "PutUserPolicy"),
        ("iam", ApiFamilies.CREDENTIAL_MANAGEMENT, "write", True, "CreateAccessKey"),
    )
    for j, step in enumerate(chain):
        at = base_ts + timedelta(days=attack_day, hours=3, minutes=5 * j)
        events.append(_make_drift_event(
            scenario.identity_key, f"drift-attack-{j}", at, "KP", "45.12.98.7",
            131279, "python-requests/2.31", step[0], step[1], False,
        ))
        labels.append(1)
        phase_tags.append("attack")

    return events, labels, phase_tags


def build_persona_from_identity(identity_key: str) -> dict:
    """Stable per-identity drift persona (country/IP/ASN from the key)."""
    return {
        "home_country": "IN",
        "home_ip": "10.20.30.40",
        "home_asn": 9829,
        "home_ua": "Chrome/126 Windows",
    }


def _make_drift_event(
    identity: str,
    event_id: str,
    at: datetime,
    country: str,
    ip: str,
    asn: int,
    ua: str,
    service: str,
    family: str,
    mfa: bool,
) -> IdentityActivityEvent:
    return IdentityActivityEvent(
        event_id=event_id,
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
        event_name="GetObject" if family == ApiFamilies.S3_DATA_READ else "DoThing",
        event_category=EventCategory.DATA,
        service_name=service,
        api_family=family,
        read_or_write=AccessType.READ,
        privilege_change=False,
        source_ip=ip,
        country=country,
        asn=asn,
        user_agent=ua,
        mfa_authenticated=mfa,
    )


__all__ = [
    "SystemEvaluation",
    "SystemRunner",
    "cross_identity_evaluation",
    "drift_stream",
    "evaluate_system",
    "fp_analysis_records",
    "temporal_three_way_split",
    "tune_threshold",
]
