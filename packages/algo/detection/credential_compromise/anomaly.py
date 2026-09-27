"""ML anomaly layer - **Part 2**.

Implements the 18-feature behavioral vector and an Isolation Forest for
*unusual combinations* of behavior - the thing deterministic per-dimension
features and rules cannot see (e.g. normal hour + normal API + novel network
together).

Engineering honesty notes:

* The forest is implemented in pure Python (``random.Random`` for
  reproducibility) because scikit-learn is not a project dependency. The
  algorithm is the standard Isolation Forest (Liu et al., 2008).
* A supervised second model slot exists but is only trainable when *labeled*
  data is supplied. Labels on synthetic datasets are marked synthetic; no
  real-world validation is claimed for them.
* Feature rows are built causally (see ``temporal.py`` and ``replay.py``);
  training/evaluation splits are time-based so no future information leaks
  into training.
"""

from __future__ import annotations

import math
import random
from typing import Callable, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from detection.credential_compromise.config import AnomalyConfig, ScoringConfig
from detection.credential_compromise.features import BehavioralFeatures
from detection.credential_compromise.schemas import (
    IdentityActivityEvent,
    IdentityProfile,
    IdentitySession,
)
from detection.credential_compromise.temporal import WindowStats

#: Stable feature ordering - the ML contract. Never reorder, only append.
FEATURE_NAMES: tuple[str, ...] = (
    "time_deviation",
    "location_deviation",
    "ip_novelty",
    "asn_novelty",
    "client_novelty",
    "region_novelty",
    "service_novelty",
    "api_novelty",
    "api_frequency_deviation",
    "read_write_deviation",
    "api_sequence_deviation",
    "privilege_anomaly",
    "mfa_anomaly",
    "session_length_deviation",
    "request_burst_score",
    "personal_baseline_deviation",
    "peer_baseline_deviation",
    "identity_risk_context",
)

FEATURE_VERSION = "fv2-2026.09"


class FeatureVector(BaseModel):
    """A normalized, fixed-order feature row for the ML layer."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    values: tuple[float, ...]
    missing: tuple[str, ...] = ()

    @property
    def names(self) -> tuple[str, ...]:
        return FEATURE_NAMES

    def as_dict(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.values))


# --------------------------------------------------------------------------- #
# Feature pipeline
# --------------------------------------------------------------------------- #


def mfa_anomaly_value(event: IdentityActivityEvent, profile: Optional[IdentityProfile]) -> float:
    """MFA state anomaly in [0, 1]; ``None`` telemetry abstains (0.0)."""
    if event.mfa_authenticated is None:
        return 0.0
    if event.mfa_authenticated:
        return 0.0
    expected = bool(profile.mfa_expected) if profile else False
    sensitive = event.privilege_change or event.event_category.value in ("signin", "management")
    if sensitive or expected:
        return 1.0
    return 0.4


def session_length_deviation_value(
    session: Optional[IdentitySession],
) -> float:
    """Log-scale deviation of an unusually long session; unknown -> 0.0.

    There is no learned per-identity session-length baseline yet, so v1 uses
    a transparent fixed reference (2 hours) - documented, configurable later.
    """
    if session is None or session.duration_seconds <= 0:
        return 0.0
    reference_seconds = 7200.0
    ratio = session.duration_seconds / reference_seconds
    return round(min(1.0, 1.0 - math.exp(-abs(math.log(max(ratio, 1e-6))))), 4)


def identity_risk_context_value(
    event: IdentityActivityEvent,
    profile: Optional[IdentityProfile],
    session: Optional[IdentitySession],
) -> float:
    """Transparent context prior in [0, 1]: who is acting, and how armed."""
    level = (profile.normal_privilege_level if profile else "UNKNOWN") or "UNKNOWN"
    level_share = {"NONE": 0.0, "LOW": 0.15, "MODERATE": 0.3, "ELEVATED": 0.45, "UNKNOWN": 0.25}.get(
        level, 0.25
    )
    value = level_share
    if event.privilege_change:
        value += 0.35
    if event.mfa_authenticated is False:
        value += 0.2
    if session is not None and session.privilege_changes > 1:
        value += 0.15
    return round(min(1.0, value), 4)


def _weighted_dimension_mean(
    features: BehavioralFeatures, config: ScoringConfig
) -> float:
    dims = features.dimension_values()
    total = sum(config.weights.values()) or 1.0
    return sum(config.weights.get(name, 0.0) * value for name, value in dims.items()) / total


def build_feature_vector(
    event: IdentityActivityEvent,
    features: BehavioralFeatures,
    *,
    windows: dict[int, WindowStats],
    burst: float = 0.0,
    config: ScoringConfig,
    personal_features: Optional[BehavioralFeatures] = None,
    peer_features: Optional[BehavioralFeatures] = None,
    profile: Optional[IdentityProfile] = None,
    session: Optional[IdentitySession] = None,
) -> FeatureVector:
    """Assemble the ML feature row. Missing values become 0.0 and are listed
    in ``missing`` so downstream consumers can distinguish absent from normal.
    """
    values: list[float] = []
    missing: list[str] = []

    def push(name: str, value: Optional[float]) -> None:
        if value is None:
            values.append(0.0)
            missing.append(name)
        else:
            values.append(round(min(1.0, max(0.0, value)), 6))

    push("time_deviation", features.time_anomaly.value)
    push("location_deviation", features.location_anomaly.value)
    push("ip_novelty", features.ip_novelty.value)
    push("asn_novelty", features.asn_novelty.value)
    push("client_novelty", features.client_novelty.value)
    push("region_novelty", features.region_novelty.value)
    push("service_novelty", features.service_novelty.value)
    push("api_novelty", features.api_novelty.value)
    push("api_frequency_deviation", features.api_frequency_deviation.value)
    push("read_write_deviation", features.read_write_deviation.value)
    push("api_sequence_deviation", features.api_sequence_deviation.value)
    push("privilege_anomaly", features.privilege_anomaly.value)
    push("mfa_anomaly", mfa_anomaly_value(event, profile))
    push(
        "session_length_deviation",
        session_length_deviation_value(session) if session is not None else None,
    )
    push("request_burst_score", burst)
    push(
        "personal_baseline_deviation",
        _weighted_dimension_mean(personal_features, config)
        if personal_features is not None
        else None,
    )
    push(
        "peer_baseline_deviation",
        _weighted_dimension_mean(peer_features, config) if peer_features is not None else None,
    )
    push("identity_risk_context", identity_risk_context_value(event, profile, session))

    assert len(values) == len(FEATURE_NAMES), "feature vector must match FEATURE_NAMES"
    return FeatureVector(event_id=event.event_id, values=tuple(values), missing=tuple(missing))


# --------------------------------------------------------------------------- #
# Isolation Forest (pure Python, deterministic via seeded RNG)
# --------------------------------------------------------------------------- #


def _c(n: int) -> float:
    """Average path length of an unsuccessful BST search over n samples."""
    if n <= 1:
        return 0.0
    harmonic = math.log(n - 1) + 0.5772156649  # log(n-1) + Euler-Mascheroni
    return 2.0 * harmonic - (2.0 * (n - 1) / n)


class _Node:
    __slots__ = ("size", "feature", "threshold", "left", "right")

    def __init__(
        self,
        size: int,
        feature: Optional[int] = None,
        threshold: Optional[float] = None,
        left: Optional["_Node"] = None,
        right: Optional["_Node"] = None,
    ) -> None:
        self.size = size
        self.feature = feature
        self.threshold = threshold
        self.left = left
        self.right = right


class IsolationForest:
    """Standard Isolation Forest over the fixed feature vector.

    ``score`` returns the raw iForest anomaly score s in (0, 1] (typical
    ~0.5, anomalies near 1). ``score_normalized`` converts it to a
    deployment-friendly [0, 1] using the *training* score distribution:
    0 for typical traffic, approaching 1 only for combinations far outside
    it. Fitting requires at least ``AnomalyConfig.min_training_rows`` rows -
    a forest fit on a handful of samples memorises instead of generalising.
    """

    def __init__(self, config: Optional[AnomalyConfig] = None) -> None:
        self.config = config or AnomalyConfig()
        self._trees: list[_Node] = []
        self._train_mean: float = 0.0
        self._train_std: float = 1.0
        self._height_limit = 0
        self.fitted = False

    # -- training ------------------------------------------------------- #

    def fit(self, rows: Sequence[Sequence[float]]) -> "IsolationForest":
        if len(rows) < self.config.min_training_rows:
            from detection.credential_compromise.exceptions import DetectionError

            raise DetectionError(
                "insufficient rows to fit the isolation forest",
                context={"rows": len(rows), "required": self.config.min_training_rows},
            )
        dim = len(rows[0])
        if any(len(row) != dim for row in rows):
            from detection.credential_compromise.exceptions import DetectionError

            raise DetectionError("feature rows must all have the same width")
        rng = random.Random(self.config.seed)
        self._height_limit = math.ceil(math.log2(max(2, self.config.subsample_size)))
        pool = [tuple(row) for row in rows]
        subsample = min(self.config.subsample_size, len(pool))
        # Standard iForest: each tree is built on its own random subsample.
        self._trees = [
            self._build_tree(rng.sample(pool, subsample), rng, 0)
            for _ in range(self.config.trees)
        ]
        scores = [self.raw_score(row) for row in pool]
        self._train_mean = sum(scores) / len(scores)
        variance = sum((s - self._train_mean) ** 2 for s in scores) / len(scores)
        self._train_std = math.sqrt(variance) or 1e-6
        self.fitted = True
        return self

    def _build_tree(self, rows: list[tuple[float, ...]], rng: random.Random, depth: int) -> _Node:
        if depth >= self._height_limit or len(rows) <= 1:
            return _Node(size=len(rows))
        feature = rng.randrange(len(rows[0]))
        values = [row[feature] for row in rows]
        low, high = min(values), max(values)
        if low == high:
            return _Node(size=len(rows))
        threshold = rng.uniform(low, high)
        left_rows = [row for row in rows if row[feature] < threshold]
        right_rows = [row for row in rows if row[feature] >= threshold]
        if not left_rows or not right_rows:
            return _Node(size=len(rows))
        return _Node(
            size=len(rows),
            feature=feature,
            threshold=threshold,
            left=self._build_tree(left_rows, rng, depth + 1),
            right=self._build_tree(right_rows, rng, depth + 1),
        )

    # -- scoring -------------------------------------------------------- #

    def _path_length(self, row: Sequence[float], node: _Node, depth: int) -> float:
        if node.feature is None:
            return depth + _c(node.size)
        if row[node.feature] < node.threshold:
            return self._path_length(row, node.left, depth + 1)  # type: ignore[arg-type]
        return self._path_length(row, node.right, depth + 1)  # type: ignore[arg-type]

    def raw_score(self, row: Sequence[float]) -> float:
        if not self._trees:
            from detection.credential_compromise.exceptions import DetectionError

            raise DetectionError("isolation forest is not fitted")
        expected = sum(self._path_length(row, tree, 0) for tree in self._trees) / len(self._trees)
        return float(2.0 ** (-expected / max(_c(self.config.subsample_size), 1e-6)))

    def score_normalized(self, row: Sequence[float]) -> float:
        """[0, 1] anomaly likelihood relative to the training distribution."""
        raw = self.raw_score(row)
        excess = max(0.0, raw - self._train_mean)
        return round(1.0 - math.exp(-excess / self._train_std), 6)

    def score(self, row: Sequence[float]) -> float:
        """Alias of :meth:`score_normalized` for pipeline use."""
        return self.score_normalized(row)


# --------------------------------------------------------------------------- #
# Optional supervised slot (logistic regression; XGBoost replaces this when
# the dependency and real labels exist)
# --------------------------------------------------------------------------- #


class SupervisedAnomalyModel:
    """Minimal logistic regression over the same feature vector.

    Trains **only** on supplied labels. When those labels are synthetic the
    instance records ``synthetic_labels=True`` and every report must carry
    that marker - synthetic labels cannot support real-world claims.
    """

    def __init__(self, *, learning_rate: float = 0.1, epochs: int = 300, l2: float = 0.01) -> None:
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.l2 = l2
        self.weights: list[float] = []
        self.bias = 0.0
        self.fitted = False
        self.synthetic_labels = False
        self.label_source = "unlabeled"

    def fit(
        self,
        rows: Sequence[Sequence[float]],
        labels: Sequence[int],
        *,
        synthetic: bool = False,
        label_source: str = "supplied",
    ) -> "SupervisedAnomalyModel":
        if len(rows) != len(labels) or not rows:
            from detection.credential_compromise.exceptions import DetectionError

            raise DetectionError(
                "supervised model needs equal-length rows and labels",
                context={"rows": len(rows), "labels": len(labels)},
            )
        dim = len(rows[0])
        self.weights = [0.0] * dim
        self.bias = 0.0
        self.synthetic_labels = synthetic
        self.label_source = label_source
        for _ in range(self.epochs):
            grad_w = [0.0] * dim
            grad_b = 0.0
            for row, label in zip(rows, labels):
                activation = self._sigmoid(self._dot(row) + self.bias)
                error = activation - float(label)
                for j in range(dim):
                    grad_w[j] += error * row[j]
                grad_b += error
            n = len(rows)
            for j in range(dim):
                grad_w[j] = grad_w[j] / n + self.l2 * self.weights[j]
                self.weights[j] -= self.learning_rate * grad_w[j]
            self.bias -= self.learning_rate * (grad_b / n)
        self.fitted = True
        return self

    def _dot(self, row: Sequence[float]) -> float:
        return sum(w * x for w, x in zip(self.weights, row))

    @staticmethod
    def _sigmoid(z: float) -> float:
        if z < 0:
            exp_z = math.exp(z)
            return exp_z / (1.0 + exp_z)
        return 1.0 / (1.0 + math.exp(-z))

    def score_proba(self, row: Sequence[float]) -> float:
        if not self.fitted:
            from detection.credential_compromise.exceptions import DetectionError

            raise DetectionError("supervised model is not fitted")
        return round(self._sigmoid(self._dot(row) + self.bias), 6)


__all__ = [
    "FEATURE_NAMES",
    "FEATURE_VERSION",
    "FeatureVector",
    "IsolationForest",
    "SupervisedAnomalyModel",
    "build_feature_vector",
    "mfa_anomaly_value",
]
