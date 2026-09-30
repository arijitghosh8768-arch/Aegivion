"""Optional supervised model — strictly gated.

A supervised model may only be trained when:
1. the data is LABELED (explicit ``label`` field), and
2. synthetic scenarios are explicitly marked ``synthetic=True``.

Real-world labels are never fabricated; unlabeled data is refused. When
the gate passes, we train a small logistic model on the frozen feature
vector (XGBoost is optional at deployment time via the same interface —
this build ships a dependency-free deterministic trainer).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Sequence

from algo.data_exfiltration.data_exfiltration.ml.feature_vector import FEATURE_NAMES, MLFeatureVector


class LabelGateError(Exception):
    """Raised when supervised training is requested on unlabeled data."""


@dataclass
class LabeledDataset:
    """A labeled dataset that knows whether it is synthetic."""

    vectors: list[MLFeatureVector]
    labels: list[int]
    synthetic: bool = False
    source: str = "unspecified"
    """Where labels came from, e.g. 'red_team_exercise' or 'incident_2024'."""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.vectors) != len(self.labels):
            raise ValueError("vectors and labels must align")
        if any(y not in (0, 1) for y in self.labels):
            raise ValueError("labels must be binary 0/1")

    @property
    def is_synthetic(self) -> bool:
        return self.synthetic


class SupervisedModelGate:
    """Decides whether supervised training may proceed."""

    MIN_PER_CLASS = 10

    def check(self, dataset: LabeledDataset) -> tuple[bool, str]:
        if not dataset.vectors:
            return False, "empty dataset"
        positives = sum(1 for y in dataset.labels if y == 1)
        negatives = len(dataset.labels) - positives
        if positives < self.MIN_PER_CLASS or negatives < self.MIN_PER_CLASS:
            return False, (
                f"insufficient labels: {positives} positive / {negatives} negative; "
                f"need >= {self.MIN_PER_CLASS} per class"
            )
        return True, "labeled data present (synthetic flag: %s)" % dataset.synthetic

    def fit_allowed(self, dataset: LabeledDataset) -> bool:
        ok, _ = self.check(dataset)
        return ok


@dataclass
class SupervisedModel:
    """Deterministic logistic model over the frozen feature vector."""

    weights: list[float]
    bias: float
    feature_version: str
    synthetic_training_data: bool
    label_source: str
    version: str = "logistic-1.0.0"

    def score(self, vector: MLFeatureVector) -> float:
        ordered = vector.ordered_values()
        z = self.bias + sum(w * x for w, x in zip(self.weights, ordered))
        return 1.0 / (1.0 + math.exp(-z))


def train_supervised(
    dataset: LabeledDataset,
    gate: SupervisedModelGate | None = None,
    *,
    lr: float = 0.3,
    epochs: int = 1500,
) -> SupervisedModel:
    """Train the supervised model; raises LabelGateError when not allowed."""
    gate = gate or SupervisedModelGate()
    allowed, reason = gate.check(dataset)
    if not allowed:
        raise LabelGateError(reason)

    rows = [v.ordered_values() for v in dataset.vectors]
    n_features = len(FEATURE_NAMES)
    weights = [0.0] * n_features
    bias = 0.0
    n = len(rows)
    for _ in range(epochs):
        grad_w = [0.0] * n_features
        grad_b = 0.0
        for row, y in zip(rows, dataset.labels):
            z = bias + sum(w * x for w, x in zip(weights, row))
            p = 1.0 / (1.0 + math.exp(-z))
            err = p - y
            for i, x in enumerate(row):
                grad_w[i] += err * x
            grad_b += err
        for i in range(n_features):
            weights[i] -= lr * grad_w[i] / n
        bias -= lr * grad_b / n

    return SupervisedModel(
        weights=[round(w, 6) for w in weights],
        bias=round(bias, 6),
        feature_version=dataset.vectors[0].feature_version,
        synthetic_training_data=dataset.synthetic,
        label_source=dataset.source,
    )
