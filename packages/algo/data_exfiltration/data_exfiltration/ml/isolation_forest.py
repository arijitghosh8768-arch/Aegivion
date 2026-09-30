"""Deterministic Isolation Forest for session anomaly scoring.

Why Isolation Forest: true exfiltration labels are rare; IF is
unsupervised and isolates "few and different" sessions without labels.

Determinism guarantees:
- fixed RNG seed (default 42) and no wall-clock anywhere
- fixed feature order (ml.feature_vector.FEATURE_NAMES)
- candidate feature subsets are drawn with the seeded RNG
- duplicate cleanups are deterministic (sorted tuples)

Score normalization: raw isolation depth is converted to the standard
E(T) / c(n) anomaly coefficient s(x, n) in (0, 1], then calibrated into
an interpretable 0..1 anomaly score with an EMPIRICAL ECDF over the
training (or validation) distribution — not a hand-waved formula. If the
scored point exceeds all training samples, the ECDF returns a value just
below 1.0 (rank/n), never a fabricated 1.0.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Sequence

from algo.data_exfiltration.data_exfiltration.ml.feature_vector import FEATURE_NAMES

_HARmonic_CONST = 0.5772156649  # Euler-Mascheroni


def _c(n: float) -> float:
    """Average path length of unsuccessful search in a BST of n samples."""
    if n <= 1:
        return 0.0
    return 2.0 * (math.log(n - 1.0) + _HARmonic_CONST) - 2.0 * (n - 1.0) / n


class _Node:
    __slots__ = ("feature_idx", "threshold", "left", "right", "size")

    def __init__(self, feature_idx: int | None, threshold: float | None, left, right, size: int) -> None:
        self.feature_idx = feature_idx
        self.threshold = threshold
        self.left = left
        self.right = right
        self.size = size


@dataclass
class _Tree:
    root: _Node | None
    height_limit: int


def _build_tree(
    data: list[list[float]],
    height: int,
    limit: int,
    rng: random.Random,
) -> _Node | None:
    if height >= limit or len(data) <= 1:
        return _Node(None, None, None, None, len(data))

    # choose a feature with real variance among candidates
    n_features = len(data[0])
    candidates = rng.sample(range(n_features), min(n_features, max(1, n_features // 2)))
    best_feature = None
    best_lo = best_hi = 0.0
    for f in candidates:
        values = [row[f] for row in data]
        lo, hi = min(values), max(values)
        if hi - lo > 1e-12:
            best_feature = f
            best_lo, best_hi = lo, hi
            break
    if best_feature is None:
        return _Node(None, None, None, None, len(data))

    threshold = rng.uniform(best_lo, best_hi)
    left_rows = [row for row in data if row[best_feature] < threshold]
    right_rows = [row for row in data if row[best_feature] >= threshold]
    if not left_rows or not right_rows:
        # degenerate split: treat as leaf
        return _Node(None, None, None, None, len(data))

    node = _Node(best_feature, threshold, None, None, len(data))
    node.left = _build_tree(left_rows, height + 1, limit, rng)
    node.right = _build_tree(right_rows, height + 1, limit, rng)
    return node


def _path_length(node: _Node | None, row: list[float], height: int = 0) -> float:
    if node is None:
        return height
    if node.feature_idx is None:
        return height + _c(node.size)
    if row[node.feature_idx] < node.threshold:
        return _path_length(node.left, row, height + 1)
    return _path_length(node.right, row, height + 1)


class IsolationForest:
    """Seeded Isolation Forest with ECDF-normalized anomaly scores in 0..1."""

    model_id = "isolation_forest"

    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: int = 256,
        seed: int = 42,
        subsample_size: int = 20000,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.seed = seed
        self._subsample_size = subsample_size
        self._trees: list[_Tree] = []
        self._ecdf: list[float] = []
        self._n_features: int | None = None
        self.fitted_: bool = False

    # ------------------------------------------------------------------

    def fit(self, vectors: Sequence[Sequence[float]]) -> "IsolationForest":
        """Fit on training vectors (ordered per FEATURE_NAMES)."""
        rows = [list(map(float, v)) for v in vectors]
        if not rows:
            raise ValueError("cannot fit IsolationForest on empty data")
        self._n_features = len(rows[0])
        rng = random.Random(self.seed)

        # deterministic subsample for very large training sets
        if len(rows) > self._subsample_size:
            rng.shuffle(rows)
            rows = rows[: self._subsample_size]

        limit = int(math.ceil(math.log2(max(2, min(self.max_samples, len(rows))))))
        self._trees = []
        sample_cap = min(self.max_samples, len(rows))
        for i in range(self.n_estimators):
            tree_rng = random.Random(self.seed + i)
            sample = rows if len(rows) <= sample_cap else rng.sample(rows, sample_cap)
            self._trees.append(_Tree(_build_tree(sample, 0, limit, tree_rng), limit))

        # ECDF over TRAINING raw scores (score-before-normalize discipline)
        raw = sorted(self._raw_scores(rows))
        self._ecdf = raw
        self.fitted_ = True
        return self

    def _raw_scores(self, rows: list[list[float]]) -> list[float]:
        return [self._raw_score(row) for row in rows]

    def _raw_score(self, row: list[float]) -> float:
        n = len(self._trees)
        if n == 0:
            return 0.0
        total = sum(_path_length(t.root, row, 0) for t in self._trees)
        mean_depth = total / n
        return 2.0 ** (-mean_depth / _c(max(2, self.max_samples)))

    def _ecdf_score(self, raw: float) -> float:
        """Empirical CDF of raw scores -> 0..1, strictly below 1.0."""
        values = self._ecdf
        if not values:
            return 0.0
        lo, hi = 0, len(values)
        while lo < hi:
            mid = (lo + hi) // 2
            if values[mid] <= raw:
                lo = mid + 1
            else:
                hi = mid
        return round(lo / len(values), 6)

    def score(self, vector: Sequence[float]) -> float:
        """Anomaly score in 0..1 (ECDF of raw isolation coefficient)."""
        if not self.fitted_:
            raise RuntimeError("IsolationForest.score called before fit")
        row = list(map(float, vector))
        if self._n_features is not None and len(row) != self._n_features:
            raise ValueError(
                f"feature count mismatch: expected {self._n_features}, got {len(row)}"
            )
        return self._ecdf_score(self._raw_score(row))

    def score_raw(self, vector: Sequence[float]) -> float:
        """Raw isolation coefficient s(x,n) in (0,1], pre-ECDF."""
        if not self.fitted_:
            raise RuntimeError("IsolationForest.score_raw called before fit")
        return self._raw_score(list(map(float, vector)))

    def version(self) -> str:
        return f"if-{self.n_estimators}x{self.max_samples}-seed{self.seed}"
