"""Optional supervised model — **Part 3**.

A *slot*, not a dependency: real destruction labels are rare, and this
project never fabricates them. The slot activates only when explicit,
declared labels exist.

- If ``xgboost`` is installed **and** labeled data is supplied, an
  ``XGBClassifier`` is trained (calibrated-style usage: raw probabilities
  are exposed, and their calibration quality is *measured*, not assumed —
  see :mod:`detection.cloud_destruction.calibration`).
- If ``xgboost`` is absent, a deterministic, dependency-free logistic
  regression (batch gradient descent) provides the same interface so the
  fusion layer and evaluation framework can be exercised end to end.
- **Synthetic-label discipline**: training/eval data built from synthetic
  fixtures carries ``label_source="synthetic"`` and results built on it
  are marked accordingly. Synthetic benchmark results are never presented
  as production performance.

No model is ever trained silently: :meth:`SupervisedDetector.fit` refuses
undeclared label sources, and empty training data returns an unfitted
model rather than inventing one.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Sequence

from detection.cloud_destruction.registry import ModelDescriptor, content_digest

__all__ = [
    "LABEL_SOURCE_SYNTHETIC",
    "LABEL_SOURCE_DECLARED",
    "SupervisedTrainingData",
    "SupervisedDetector",
    "SupervisedPrediction",
]

LABEL_SOURCE_SYNTHETIC = "synthetic"
LABEL_SOURCE_DECLARED = "declared"


@dataclass(frozen=True)
class SupervisedTrainingData:
    """Labeled training rows with an **explicit** label provenance."""

    rows: Sequence[Sequence[float]]
    labels: Sequence[int]
    label_source: str
    """``"declared"`` (real, reviewed labels) or ``"synthetic"``."""
    description: str = ""

    def __post_init__(self) -> None:
        if self.label_source not in (LABEL_SOURCE_DECLARED, LABEL_SOURCE_SYNTHETIC):
            raise ValueError(
                f"label_source must be '{LABEL_SOURCE_DECLARED}' or '{LABEL_SOURCE_SYNTHETIC}'"
            )
        if len(self.rows) != len(self.labels):
            raise ValueError("rows and labels must have the same length")

    @property
    def is_synthetic(self) -> bool:
        return self.label_source == LABEL_SOURCE_SYNTHETIC


@dataclass
class SupervisedPrediction:
    """Calibrated-style probability from the supervised slot."""

    probability: float
    model_name: str
    model_version: str
    label_source_used: Optional[str] = None


class _LogisticModel:
    """Minimal deterministic logistic regression (batch gradient descent)."""

    def __init__(self, learning_rate: float = 0.1, epochs: int = 300, l2: float = 1e-3) -> None:
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.l2 = l2
        self.weights: list[float] = []
        self.bias = 0.0

    @staticmethod
    def _sigmoid(z: float) -> float:
        if z < -35:
            return 0.0
        if z > 35:
            return 1.0
        return 1.0 / (1.0 + math.exp(-z))

    def fit(self, rows: Sequence[Sequence[float]], labels: Sequence[int]) -> None:
        if not rows:
            return
        d = len(rows[0])
        self.weights = [0.0] * d
        self.bias = 0.0
        n = float(len(rows))
        for _ in range(self.epochs):
            grad_w = [0.0] * d
            grad_b = 0.0
            for row, label in zip(rows, labels):
                z = self.bias + sum(w * x for w, x in zip(self.weights, row))
                error = self._sigmoid(z) - float(label)
                grad_b += error
                for j in range(d):
                    grad_w[j] += error * row[j]
            for j in range(d):
                grad_w[j] = grad_w[j] / n + self.l2 * self.weights[j]
            grad_b = grad_b / n
            for j in range(d):
                self.weights[j] -= self.learning_rate * grad_w[j]
            self.bias -= self.learning_rate * grad_b

    def predict_proba(self, row: Sequence[float]) -> float:
        z = self.bias + sum(w * x for w, x in zip(self.weights, row))
        return self._sigmoid(z)


class SupervisedDetector:
    """Optional supervised classification slot (XGBoost-if-present)."""

    def __init__(self, seed: int = 1337) -> None:
        self.seed = seed
        self._model: Optional[object] = None
        self._backend: Optional[str] = None
        self._label_source: Optional[str] = None
        self._n_features = 0

    # ------------------------------------------------------------------ #
    # Training
    # ------------------------------------------------------------------ #

    def fit(self, data: SupervisedTrainingData) -> "SupervisedDetector":
        """Train on explicitly-declared (or clearly-synthetic) labels."""
        if not data.rows:
            self._model = None
            return self
        self._n_features = len(data.rows[0])
        self._label_source = data.label_source
        try:
            import xgboost as xgb  # type: ignore[import-not-found]

            params = {
                "max_depth": 4,
                "n_estimators": 120,
                "learning_rate": 0.1,
                "subsample": 0.9,
                "colsample_bytree": 0.9,
                "eval_metric": "aucpr",
                "random_state": self.seed,
                "n_jobs": 1,
            }
            model = xgb.XGBClassifier(**params)
            model.fit(list(data.rows), list(data.labels))
            self._model = model
            self._backend = "xgboost"
        except ImportError:
            logistic = _LogisticModel()
            logistic.fit(data.rows, data.labels)
            self._model = logistic
            self._backend = "logistic"
        return self

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    @property
    def backend(self) -> Optional[str]:
        return self._backend

    @property
    def label_source(self) -> Optional[str]:
        return self._label_source

    def descriptor(self) -> ModelDescriptor:
        params = {"seed": self.seed}
        version = "1.0.0"
        if self._backend == "logistic":
            params.update({"learning_rate": 0.1, "epochs": 300, "l2": 1e-3})
            version = "logistic-1.0.0"
        return ModelDescriptor(
            model_name="supervised_classifier",
            model_version=version,
            component="supervised",
            params_digest=content_digest(params),
            extra={
                **params,
                "backend": self._backend,
                "label_source": self._label_source,
                "synthetic_labels": self._label_source == LABEL_SOURCE_SYNTHETIC,
            },
        )

    # ------------------------------------------------------------------ #
    # Inference
    # ------------------------------------------------------------------ #

    def predict_row(self, row: Sequence[float]) -> Optional[SupervisedPrediction]:
        if not self.is_fitted:
            return None
        if len(row) != self._n_features:
            raise ValueError(
                f"feature mismatch: expected {self._n_features}, got {len(row)}"
            )
        if self._backend == "xgboost":
            proba = float(self._model.predict_proba([list(row)])[0][1])  # type: ignore[union-attr]
        else:
            proba = float(self._model.predict_proba(row))  # type: ignore[union-attr]
        proba = max(0.0, min(1.0, proba))
        return SupervisedPrediction(
            probability=proba,
            model_name="supervised_classifier",
            model_version=self.descriptor().model_version,
            label_source_used=self._label_source,
        )
